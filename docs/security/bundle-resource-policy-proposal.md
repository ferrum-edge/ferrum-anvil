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
The app preview uses the same interactive KDF metadata as production write,
without deriving a key. Testing KDF metadata would undercount an encrypted
manifest by one byte (`m_cost` 1024 rather than 65536).
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
The candidate checkout names the exact PR head; each snapshot has its own Cargo
target directory. Cargo's artifact output identifies each test executable, whose
SHA-256 is checked before generation/timing. The harness verifies its embedded
snapshot/variant identity before opening and asserts the named variant's limits
and expected accept/refuse result,
rather than inferring the variant from whichever library was built last.
Generation/builds run outside measurement; OS time measures the recorded test
executable directly, and each opening gets a fresh process.
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
Exact serialized boundary regressions exercise preview, write and open with a
fixed prepared timestamp, production KDF metadata, the 41-byte sealed envelope,
and one-byte entry/aggregate excess. They show the one-byte encrypted-manifest
undercount with testing KDF parameters. An app regression covers share-safe and
encrypted export at exactly 32 MiB per attachment and one byte over.

Initial hosted qualification at `fecc636348fdedf5314f9505ba77fcd96860e574`
[failed during fixture generation on Linux and macOS](https://github.com/ferrum-edge/ferrum-anvil/actions/runs/37194746083):
the completed ZIP was read through a write-only `File::create` handle. It produced
no opening RSS results. Generation now closes that handle and reopens read-only;
the original shared-target build also could not establish snapshot provenance.
The [hosted Linux formatter diff](https://github.com/ferrum-edge/ferrum-anvil/actions/runs/37194746032/job/111414173216)
has been applied literally. The initial macOS boundary test also failed import
validation because its synthetic secret had an invalid ID and no workspace owner;
the fixture now carries a valid ID and an included owner workspace.
Exact-source hosted RSS qualification passed on `843e750eb2a27636b3ff9fd19b5b6d936f3b71cd`
in [run 37195941241](https://github.com/ferrum-edge/ferrum-anvil/actions/runs/37195941241):
Linux job 111417695811 and macOS job 111417695940 both succeeded. Each host ran
21 fresh-process cases using separate compiled variants and harness-embedded
snapshot/variant provenance. The scalar artifacts are
[Linux 11300537977](https://github.com/ferrum-edge/ferrum-anvil/actions/runs/37195941241)
(SHA-256 `753f7b4d7e6996426dcebc2618c9f71c4da0812081b31716e76f6b5325ca6f0f`) and
[macOS 11300837077](https://github.com/ferrum-edge/ferrum-anvil/actions/runs/37195941241)
(SHA-256 `091422fbf09cb7c2c79e89f52332945e00f4c7568f573e15670fef18ff62d547`).
Linux GNU `time` values reported in KiB were converted to bytes; macOS values are
the reported `maximumresidentsetsize` bytes. Representative maximum RSS was:

| Case | Linux bytes | macOS bytes |
|---|---:|---:|
| candidate `proposal_exact` | 77,385,728 | 74,760,192 |
| candidate `metadata_exact` | 108,961,792 | 107,069,440 |
| candidate `refused_released_exact` | 24,735,744 | 22,085,632 |
| preflight `released_exact` | 1,099,431,936 | 1,018,937,344 |
| released `released_exact` | 2,175,176,704 | 1,648,197,632 |

The candidate boundary case was below half of both measured baselines on each
host, and the ceiling control passed. Invalid metadata and one-byte over-limit
refusals had controlled low RSS. These are measurements of synthetic source-test
binaries. They are not measurements of released desktop binaries or a legitimate
export corpus, and do not prove worst-case behavior, OOM safety, or whole-process
DoS resistance.

The measurement run does not make the ordinary CI result green. On the same
`843e750` source, [ordinary CI run 37195941263](https://github.com/ferrum-edge/ferrum-anvil/actions/runs/37195941263)
failed on Linux, macOS and Windows because Clippy's `option_env_unwrap` lint
rejected `.expect()` on the harness's compile-time `option_env!` values. Commit
`722bb8bc844feabe63e9ec6ae436d041be1e0878` changes only that compiled-metadata
extraction to `let Some(...) else`; it does not change limits, runtime behavior,
or harness identity. The correction received a fresh independent harness review
with five APPROVED findings. The rerun of the resource qualification on that exact head
[passed on Linux and macOS](https://github.com/ferrum-edge/ferrum-anvil/actions/runs/37196753225).
Its ordinary [canonical CI run](https://github.com/ferrum-edge/ferrum-anvil/actions/runs/37196753237)
was still in progress at this check: Linux and Windows Rust jobs had passed, while
macOS Rust tests were still running. Fresh final-head canonical CI is therefore
still required. No local project code was run.

These byte limits do not eliminate all DoS: ZIP central-directory parsing happens
before the count cap, input/archive buffers and parsed JSON/history can amplify
memory, and vault plaintext adds overhead. Existing unauthenticated KDF bounds
still permit 256 MiB memory and substantial CPU work. Share-safe hashes do not
authenticate authors. The hosted measurements establish RSS only for the tested
synthetic cases; they do not establish a universal resident-memory cap or OS OOM
behavior.

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
