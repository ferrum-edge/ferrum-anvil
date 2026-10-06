# Portable bundle resource policy

Status: adopted. An owner-delegate decision on 2026-10-06 set the portable
bundle limits to 256 MiB total and 128 MiB per entry. That is four times below
the 1 GiB/512 MiB that `anvil-v0.1.0` and `anvil-v0.1.1` accept. The same
decision added:

- a budget on parsed JSON;
- a check of the ZIP end-of-central-directory record before the directory is
  indexed;
- a 128 MiB cap on newly attached files.

It declined the staged large-archive alternative (see the last section).

The policy addresses the bundle preview and import path of GHSA-jqq4-v58m-6fcw.
An untrusted bundle could make Anvil exhaust memory while it was previewed.
Residual risks are listed below. This document claims no release or patched
version.

## Limits

| Limit | Value | Counts |
|---|---:|---|
| Total inflated bytes | 268,435,456 (256 MiB) | every entry, metadata included |
| Inflated bytes per entry | 134,217,728 (128 MiB) | the manifest, the checksum list, the objects, the history, each attachment and the sealed vault |
| JSON values | 4,194,304 (4 Mi) | the manifest, checksum list, objects, history and vault plaintext together |
| Entries | 20,000 | every central-directory record, empty and duplicate ones included |
| Compression ratio | 200 | each entry, as the integer quotient inflated / max(compressed, 1) |
| Central directory | 4,397 bytes per declared entry | 46 fixed bytes, a 255-byte name, and 4 KiB for the extra fields and comments that zip tools add |
| Attached file | 134,217,728 (128 MiB) | each file attached from now on |

Every limit is inclusive: a bundle exactly at a limit opens, and one byte, value
or entry over it is refused. Metadata has no separate, smaller cap. Bundle
preview, import and export all use the same constants
(`anvil_portability::bundle::{MAX_TOTAL_BYTES, MAX_ENTRY_BYTES, MAX_JSON_NODES,
MAX_ENTRIES, MAX_RATIO}`).

## Opening a bundle (preview and import)

1. **End records.** These checks run before the `zip` crate indexes the central
   directory, using the raw bytes of the end-of-central-directory records.
   - `zip` reserves memory for every entry a record declares. If the last record
     fails, it falls back to earlier ones. So every record in the file is
     checked.
   - A ZIP64 end record is refused anywhere in the file. Bundles never need
     ZIP64, and only ZIP64 can declare more than 65,535 entries.
   - The last record must declare at most 20,000 entries. Its directory must fit
     before the record, within 4,397 bytes per declared entry.
2. **Directory.** The central headers are walked without inflating anything.
   This walk enforces the following before any entry is expanded:
   - the entry count, including duplicate raw names that the zip name index
     hides;
   - the allowed names and regular-file types;
   - the per-entry size and ratio;
   - the declared total;
   - the presence of the manifest, checksum list and objects.
3. **Byte budget.** Before each entry is read:
   - Its declared size must fit both the per-entry limit and the bytes that
     remain. Only then is its buffer reserved.
   - Every byte actually inflated is charged against the one remaining total,
     with no refunds. Metadata whose buffer is later dropped is charged too.
   - Each read is capped at the declared size plus one sentinel byte, so a size
     that does not match the declaration stops the opening. The sentinel is
     never retained.
   - Entries are hashed as they are read. Attachments move into the opened
     graph without a second copy.
4. **JSON budget.** Each JSON entry is counted from its text before it is
   parsed, without allocating. The entries are the checksum list, the manifest,
   the objects, the vault plaintext (once authenticated) and the history.
   - Every string (object keys included), every object or array, and every bare
     number, `true`, `false` or `null` counts as one value.
   - All of these entries share one budget of 4,194,304 values. The entry that
     takes the total over it is refused before serde allocates anything for it.

### Why a JSON value budget

The byte budget bounds the text that is retained, not what parsing it costs.
Anvil builds `serde_json` with `preserve_order`, so every parsed `Value` takes
80 bytes. An object member also costs 120 bytes, counted here as two values.

Without a value budget, a share-safe bundle of about 1 MiB could expand to about
5 GiB of heap:

- Its `objects.json` holds `{"requests":[0,0,0,…]}`: 128 MiB of text, compressed
  within the 200 ratio.
- Each two-byte `0,` becomes an 80-byte `Value`, giving 64 Mi values.
- These are parsed before the objects' schema can refuse them.
- A history entry of `0` lines did the same, as did, about 8 to 12 times over,
  manifests and checksum lists made of empty strings.

Counting values from the text keeps parsing proportional to the byte budget,
though not small:

- **Parsed:** at most 4 Mi values × 80 bytes, about 320 MiB, beside the
  256 MiB byte budget. While the largest array grows it briefly takes up to
  about twice that.
- **Typed:** the parsed objects are then converted into typed records, while
  the parsed tree is consumed. A typed record can cost far more than the
  values that describe it: a minimal request revision of about 13 values
  becomes a full request with every default setting, an estimated 1 to
  2.5 KB. A bundle that spends the whole budget on such records (about
  320,000 of them) could reach an estimated 0.6 to 1 GiB of typed objects,
  plus growth while their list fills.
- **Worst case:** so the parse and conversion of `objects.json` may peak at
  up to about 1 GiB, beside the inflated bytes and, for an encrypted bundle,
  key derivation. These are estimates from struct sizes, not measurements:
  no hosted case builds this shape yet. Real exports, at about 17 bytes per
  value (below), stay far from it.

The check is lexical and runs before any parse, so typed parses (the manifest,
checksums and vault payload) are covered as well as `Value` trees.

Typed deserialization of `objects.json` alone was not chosen. Import still has
to read the objects as JSON values to check schemas and to restore vault
literals by JSON pointer. History records are themselves `Value`s. And typed
structs still carry `Value` fields.

The budget leaves room for real workspaces. An exported `objects.json` holds
about one value per 17 bytes. 4 Mi values is therefore about 68 MiB of objects,
or tens of thousands of requests, before history.

## Exporting a bundle

- The size and count of every attachment are checked before the objects are
  prepared.
- The exporter then counts the exact serialized length of each entry through a
  bounded writer, and counts the JSON values that import will charge. Entries
  counted: the pretty objects, the JSONL history, the manifest with production
  key-derivation metadata, the checksum list, and the vault plaintext plus its
  41-byte envelope.
- Export uses the same byte, value and entry budgets. It does all of this before
  any payload buffer, ZIP output or key derivation.
- An export over any limit is refused in both preview and write, naming the
  entry and the budget. Exports are never split.
- Entries above the ratio rule are rewritten as Stored, so a highly compressible
  valid export still opens.
- The finished archive is checked against the import preflight before its bytes
  are returned, including the end-record check. An attached file that is itself
  a ZIP64 archive can carry its ZIP64 end records into the bundle unchanged
  (an attachment over the ratio rule is stored, and deflate keeps incompressible
  data as it is). Import refuses any bundle holding one, so export refuses it
  too, naming the file and the request or dataset that holds it. Re-create that
  archive without ZIP64, or link it instead of attaching it.
- Limit errors name entries and budgets, never secret values.

## Attachments

- **New attachments.** A file larger than 128 MiB is refused when it is
  attached, whether to a request body, a multipart part or a dataset. The error
  names the file and suggests linking it instead. Linked files are never bundled
  and can still be sent up to 256 MiB.
- **Older attachments.** A file stored before this cap cannot be exported.
  Export preview and write then fail with an error that names the file and the
  request or dataset that holds it.

## Compatibility and migration

These bundles open if they are within the limits:

- format 1 share-safe bundles;
- format 2 share-safe and encrypted-transfer bundles.

Format 1 encrypted vaults, which bound nothing else in the archive, stay refused.
Because 256 MiB includes metadata, two full 128 MiB attachments cannot share
one bundle.

A bundle written by an earlier Anvil is refused if it has any of these:

- more than 256 MiB in total;
- an entry over 128 MiB;
- more than 4 Mi JSON values.

The refusal reads `archive exceeds safety limits: …` and names the entry. To
move such a workspace:

1. Open it in the Anvil that exported it.
2. Export again in parts, in one of these ways:
   - one workspace per bundle;
   - without history;
   - with large files linked instead of attached, or removed.

Full ANVILBAK backups are not bundles and are outside this policy.

## Hosted qualification

`.github/workflows/bundle-resources.yml` runs on pull requests that touch the
bundle code, on Ubuntu 24.04 and macOS 15. It compares three sources:

- this policy;
- the landed preflight `76ed2bc3569bae64e691ecbf1a16e17bf7743107`, which
  preserved 1 GiB/512 MiB;
- the released 0.1.1 source `d69aa97fbe0cb670a1a6a0462c8826a820144bf6`.

How the run is set up:

- Each source builds the same ignored harness
  (`crates/anvil-portability/tests/bundle_resources.rs`) in its own target
  directory.
- The test executable's SHA-256 is recorded and checked before it runs.
- The harness checks its embedded source and variant before it opens anything.
- Every case opens in a fresh process, measured by the OS `time`. On Linux that
  process is limited to 4 GiB of virtual memory.

The fixtures are synthetic and streamed:

- exact 256 MiB/128 MiB and exact 1 GiB/512 MiB bundles;
- one byte over the entry and total limits;
- an invalid manifest and an invalid checksum list;
- an exact 128 MiB manifest;
- `json_nodes_over`, the 128 MiB `{"requests":[0,0,…]}` objects entry described
  above. Only this policy runs it, because the earlier sources would parse it
  whole.

The regression ceilings are not app limits:

- 1 GiB for every case of this policy, and 3 GiB for the baselines;
- 256 MiB for early refusals;
- 512 MiB for `json_nodes_over`;
- the boundary case must stay below half of each 1 GiB baseline.

Peak RSS at `2a91360702a0023b4fe8a40e1a406c610190510b`, in
[run 37453622679](https://github.com/ferrum-edge/ferrum-anvil/actions/runs/37453622679).
Linux values are GNU `time` KiB converted to bytes; macOS values are as reported.

| Source and case | Linux bytes | macOS bytes |
|---|---:|---:|
| this policy, exact 256 MiB/128 MiB | 281,530,368 | 279,003,136 |
| this policy, exact 128 MiB manifest | 410,939,392 | 408,928,256 |
| this policy, 1 GiB bundle (refused) | 24,752,128 | 22,052,864 |
| this policy, entry one byte over (refused) | 9,932,800 | 7,372,800 |
| this policy, total one byte over (refused) | 12,304,384 | 9,502,720 |
| landed preflight, exact 1 GiB/512 MiB | 1,099,362,304 | 1,085,227,008 |
| released 0.1.1, exact 1 GiB/512 MiB | 2,174,164,992 | 1,582,743,552 |

The `json_nodes_over` case and the end-record checks were added after that run.
The same workflow measures them on every later head.

These are measurements of synthetic source-test binaries. They are not
measurements of released desktop binaries or of a corpus of real exports.

## Residual risks

- **Input buffer.** The desktop app reads the whole chosen file before opening it
  (up to 2 GiB for a bundle import). The bundle limits apply to what is inflated
  and parsed from it, not to the file.
- **Backups.** The import dialog sends ANVILBAK backups to the backup restore
  preview. With the backup's own passphrase, which an attacker who made it can
  supply, that preview decrypts up to 2 GiB (`MAX_BACKUP_BYTES`). Backups are
  outside this policy.
- **Key derivation.** A bundle's Argon2id costs are unauthenticated input. They
  are bounded like a profile's own (up to 256 MiB of memory) and add to an
  encrypted bundle's peak, alongside its parsed objects.
- **Fallback end records.** A ZIP32 end record that `zip` falls back to can still
  make it index up to 65,535 entries before the directory walk refuses them.
  That indexing is bounded by the file.
- **Transient growth.** Peak memory is above the retained figures while arrays
  grow, and it includes the allocator's own overhead.
- **Typed conversion.** The value budget bounds the parsed tree, not the typed
  records built from it. For records that are small as JSON but large as typed
  structs, conversion may take an estimated 0.6 to 1 GiB (see "Why a JSON
  value budget"). It is bounded by the value budget, but not measured.
- **Concurrency.** The desktop app runs one import preview or apply at a time,
  so previews do not multiply these costs. Export previews work on local data
  only.
- **Authorship.** Share-safe checksums detect corruption; they do not
  authenticate who wrote a bundle.

## Alternative not selected: staged large archives

This alternative would keep 1 GiB/512 MiB acceptance by staging bundles on disk.
It would add a file-backed `StagedOpened` alongside `Opened`:

- The input file would be read by seeking, not held in memory.
- Attachments would be streamed and hashed into private temporary files, exposed
  as hash, length and read handles.
- Objects and history would be staged and decoded incrementally during preview
  and apply.

It would need its own policies for parser and live-object limits, disk quota,
cumulative work, cancellation and cleanup, including crash recovery. It would
also need an API migration across the portability, app and storage crates. The
owner delegate chose the bounded in-memory policy above instead.
