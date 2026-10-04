# Portable bundle resource policy: unmerged owner-approval candidate

Status: implemented on a proposal branch only; no human approval, default-main
activation, release, patched-version claim or advisory closure is authorized.
GHSA-jqq4-v58m-6fcw remains partially addressed by PR #303, landed as
`76ed2bc3569bae64e691ecbf1a16e17bf7743107`, which preserved 1 GiB/512 MiB.
Anvil `anvil-v0.1.1` and `anvil-v0.1.0` were published on October 1, 2026.
Reducing accepted archives and export behavior therefore needs a product decision;
the advisory's scanned-snapshot scope does not establish affected binary ranges.

## Concrete 64 MiB/32 MiB policy

`bundle::MAX_TOTAL_BYTES` is 67,108,864 and `MAX_ENTRY_BYTES` is 33,554,432.
Both boundaries are inclusive; manifest, checksums, objects, history, attachments
and vault ciphertext use one policy. Metadata has no additional smaller cap.
The 20,000-entry and integer-quotient ratio limit of 200 remain unchanged.
Directory declarations must fit before any entry expansion. A reservation check
precedes allocation; every actual successful read consumes the same remaining
total, including metadata whose byte buffers are later dropped. There are no
refunds. Declared/actual mismatches stop opening, with at most one non-retained
sentinel byte beyond the entry/remaining bound. Hashing is incremental, and
attachments move directly into `Opened.graph` without a retained clone.

Preview and write count actual serialized JSON/JSONL lengths through a bounded
writer, including the manifest, checksum list and the sealed vault's 41-byte
envelope overhead. Attachment sizes/counts are checked before object preparation;
complete preflight precedes payload buffers, ZIP output and key derivation.
Write borrows attachment bytes. It checks the finished ZIP against import
preflight; entries exceeding the compression-ratio rule are rewritten as Stored,
so highly compressible valid exports remain importable, with larger file sizes.
Vault AAD and checksums still bind the same inflated bytes. Limit errors name
entries/budgets, never secret payloads. Write returns bytes only after validation;
existing callers write destination files after success, so limit refusal cannot
partially write a destination. Export preparation still allocates parsed objects.

Compatibility: format 1 share-safe and format 2 share-safe/encrypted transfers
within policy remain supported; unbound format 1 vaults remain refused. Older
archives over either limit are refused by normal preview/import. Exact 64 MiB
includes metadata, so two complete 32 MiB attachments cannot fit together.
Oversized exports are refused in preview/write; no splitting or exception path
is introduced. Full ANVILBAK backups and their reader are outside this candidate.

## Hosted qualification and remaining uncertainty

`bundle-resources.yml` is a read-only PR/manual workflow on Ubuntu 24.04/macOS 15.
It compares this candidate, landed preflight and pinned released 0.1.1 source
`d69aa97fbe0cb670a1a6a0462c8826a820144bf6`, using the same ignored test harness.
Generation/builds run outside measurement; each opening gets a fresh process.
Synthetic streamed fixtures cover exact 1 GiB/512 MiB and 64 MiB/32 MiB, one-byte
entry/total excess, invalid manifest/checksums and an exact 32 MiB valid manifest.
Fixture archives are capped at 64 MiB compressed, generation at 1 GiB inflated;
Linux opening is capped at 4 GiB virtual memory, and hosted steps have timeouts.
GNU time reports RSS in KiB; macOS time reports bytes. Scalar logs/TSV only are
uploaded. Fixture regression ceilings (512 MiB candidate, 3 GiB baselines,
256 MiB early refusals) allow allocator/runner variance; they are not app limits.
Candidate boundary RSS must also be below half each 1 GiB baseline's measured RSS.
Ordinary hosted CI retains format/vault positives and read-counter barriers on
Linux/macOS/Windows. No existing job guard or trusted-policy exception changes.
Measured results: **pending hosted execution**; no local project code was run.
Root must link exact-head runs/artifacts and independently review results before
asking for approval. Synthetic data is not a legitimate export corpus, desktop
concurrency, a binary measurement, Windows RSS qualification or a worst-case proof.

These byte limits do not eliminate all DoS: ZIP central-directory parsing happens
before the count cap, input/archive buffers and parsed JSON/history can amplify
memory, and vault plaintext adds overhead. Existing unauthenticated KDF bounds
still permit 256 MiB memory and substantial CPU work. Share-safe hashes do not
authenticate authors. Peak RSS and OS OOM behavior remain unverified until hosted
runs; bounded synthetic results cannot establish a universal resident-memory cap.

## Alternative preserving large-archive compatibility

Keep 1 GiB/512 MiB acceptance, but introduce a file-backed `StagedOpened` alongside
`Opened`: seek the input file instead of retaining archive bytes; stream/hash
attachments into private temporary files and expose hash/length/read handles.
Preview and apply must consume those handles instead of `BTreeMap<String, Vec<u8>>`;
leaving the large owned-byte path active retains the advisory's memory risk.
Stage objects/history too and decode incrementally during preview/apply, with
explicit parser/live-object, disk-quota, cumulative-work and cancellation policy.
Verify all digests/vault binding before store mutation; preserve checkpoint and
transaction semantics. Reserve disk before writes, use private permissions, avoid
logging plaintext, and clean staging on failure/cancellation/drop plus crash recovery.
Preserving large metadata acceptance needs a lazy representation and caller changes,
not merely file-backed attachments. Portability/app/storage owners must coordinate
that API migration and approve staging costs; it is not implemented here.

Root owns the draft PR, independent review and hosted qualification. Only after
those are concrete should product/security owners choose 64 MiB/32 MiB plus export
refusal, or staged compatibility preservation. No owner decision is assumed.
