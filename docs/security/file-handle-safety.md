# Retained file and export handles — DRAFT

Owner decision: **root**. This branch is a review candidate, not an approved
compatibility change or a qualified fix. Do not close the advisory or claim a
patched release from this work. The assignment's requirement for cross-platform
handle-relative atomic rename is **not yet satisfied**.

The assigned source base is `4254ea84c101bdc9231a4c6f455421e22468d0ec`.
[GHSA-6hc8-xjvq-478g](https://github.com/ferrum-edge/ferrum-anvil/security/advisories/GHSA-6hc8-xjvq-478g)
reports an ancestor rename followed by symlink/junction replacement between
canonicalization and a fresh pathname open/create. The advisory's original
sealed snapshot is a different revision; neither it nor this static inspection
establishes the affected released binaries.

## Implemented candidate

Native selection canonicalizes the chooser result for its existing binding key,
then opens each directory component separately from the filesystem root with
`open_dir_nofollow`. Each lookup is relative to the preceding retained handle.
Application code never reopens the absolute canonical pathname for data I/O.
The complete directory chain remains alive, including on Windows where the
library denies delete sharing on directory handles. Opened Windows objects are
also checked for `FILE_ATTRIBUTE_REPARSE_POINT`, rather than treating a regular
file classification alone as sufficient.

Read selections keep the original regular-file descriptor open. Each read opens
only its leaf through the retained parent, refuses links/reparse objects and
non-regular files, and compares the opened descriptor's device/inode or volume
serial/file index with the original before reading. Keeping the original open
prevents its ID from being recycled during that selection. Unix opens remain
nonblocking and do not acquire a controlling terminal. Both metadata size and
the actual read remain bounded for the purpose. Certificate validation and
private-key vault ingestion consume these same opened objects. Private-key grants
remain unavailable through renderer reads, single-use, vault-bound and fenced
through the existing zeroizing claim and guarded secret transaction.

Referrer records, relocation transactions, imports remaining inert, workspace
checks, grant purpose, token opacity, grant bounds, TTL and dialog generation
checks stay in their existing services. No IPC, chooser UI, spec source/approval
binding, identity backup, HTTP or transport source is changed. `FileGrants`
method signatures remain compatible with the separate #307 byte-approval work.
`StoreAttachments` gains an internal retained-selection map; external literal
construction of that public struct is therefore a Rust source-compatibility
change even though its renderer contract does not change.

## Linked-binding decision required

The released binding record stores a canonical **path**, not persistent file or
directory authority. Reopening that path after restart cannot recover the
previously selected object. Saving just ordinary file IDs would still need an
explicit identity-reuse, filesystem/remount, atomic-editor-replacement and
migration policy; treating the current object as selected would silently grant
replacement authority.

This concrete draft leaves the stored record format unchanged and treats old
records as inert until the native chooser supplies a new session selection.
Lock revokes the shared selections; an old request context cannot regain its
file authority after unlock or reselection. The last opened App session dropping
also revokes its selections. An in-flight descriptor read may finish if it began
before revocation; no filesystem operation runs under the selection mutex.

In-place edits remain readable. An editor saving by atomic replacement needs
native reselection, preserving the same binding ID and referrer. On POSIX, an
ancestor rename after selection leaves the original retained directory usable;
its new pathname or the replacement junction/symlink is not authorized. Windows
may refuse that ancestor rename while the directory chain is retained. Status
uses the opened object's metadata without reading data bytes.

**Root must approve or replace this policy before integration.** Restart and
lock now require reselection even for legitimate existing bindings, and a
separately opened CLI process cannot use a desktop's retained handles. The
positive restart/CLI behavior of the released path-only contract is not
preserved. Alternatives require a reviewed persistent binding format and
permission/migration policy, or an explicit capability-transfer design. This
document does not assert approval for either alternative.

Retained chains consume descriptors. The linked-selection registry currently
has no new eviction/resource policy; stale records removed by import are not
used for new contexts, but their handles may remain cached until session lock
or close. Resource bounds and stale-cache cleanup need root review.

## Export and publish decisions required

The selected export parent is retained from grant issuance through exclusive
temporary creation, write, file `sync_all` and publication. Temporary and final
names are single components. Bundle temporaries retain Unix mode `0600`.
Directory, symlink, reparse and ordinary occupied destination entries are all
refused without following them; no existing leaf is opened for truncation.

A check of the selected destination's owner/type/ID followed by an overwriting
rename cannot exclude a foreign replacement between those steps on POSIX.
Therefore this draft refuses **every occupied destination**, including the
legitimate existing file. Publication itself also refuses an occupied name,
including one planted after the precheck. No destination ownership inference is
used to authorize an overwrite. This intentionally changes existing-file export
behavior and the old symlink-replacement positive; root must decide the contract.

Linux and macOS use safe `rustix::fs::renameat_with(..., NOREPLACE)` relative to
the retained parent. Windows uses cap-std's no-clobber hard-link publication.
That Windows operation is **not atomic rename** and leaves the `.partial` source
as an additional link to the output. It relies on the retained directory chain
for the library's pathname-based hard-link implementation. It does not meet the
requested native handle-relative rename requirement and needs replacement.

Temporary identity is checked on an opened object before publication, and the
published object is checked afterward. These checks are **not a source-name
compare-and-swap**. An actor able to replace the temporary leaf after its last
check can cause the foreign source to be moved/published inside the selected
directory before the postcheck returns `Changed`. The deterministic
`draft_publish_blocker_a_name_swap_after_identity_check_is_detected_but_not_rolled_back`
test intentionally records this remaining blocker. A check-and-rename loop is
not a remediation for it. Root needs an audited file-descriptor/handle publish
primitive on each OS, or a separately approved staging/permission contract.

No uncertain temporary/final pathname is unlinked on failure or rolled back.
A foreign replacement and our abandoned partial are preserved, even if that
leaks a partial. Windows keeps a partial on successful publication too. These
leaks can carry export data with the original purpose's permissions. Parent
directory power-loss durability is not claimed by the file-only fsync.

The existing grant reservation semantics remain: `take` linearizes a write
before revocation; a reserved write may finish after `revoke_all`. A failed
write is readmitted only in its original generation, with its original TTL.
The barrier test revokes during fsync-to-publish without blocking on an I/O
mutex. Private-key vault commit fencing is unchanged. Root's concurrency review
must decide whether exports instead need cancellation before publication and
what atomic commit boundary could provide that without starving lock/revocation.
Expired, evicted, misused and revoked grant handles are retired outside the
grant mutex; linked-selection handle retirement likewise releases the mutex
before closing descriptors.

## Dependency provenance and lock handoff

Published `cap-std`, `cap-primitives` and `cap-fs-ext` **4.0.3** archives were
downloaded as data, unpacked and inspected. Their SHA-256 values match the
crates.io sparse index; none is yanked. A 5.0.0 archive and upstream tag could
not be verified, so this candidate does not depend on a guessed 5.x version.

| Archive | SHA-256 |
| --- | --- |
| cap-std 4.0.3 | `c1ec78e242cfa2cfe276807ac2ecc00315a6c97786977414bcd1c3963b6c91b8` |
| cap-primitives 4.0.3 | `8b5f74729fd2f44701d1a8eb47e906cdb3ccd9ec0f02baad85a744b791940b18` |
| cap-fs-ext 4.0.3 | `56ff379b70af8e08307a8f65e7040c7301cb4a572538ade16b4984f0da77847f` |

All three `.cargo_vcs_info.json` files name upstream commit
`b7acf8e8807fe3fab991884d2208b7e03d35a409`. Primary implementation evidence:
[component no-follow directory opens](https://github.com/bytecodealliance/cap-std/blob/b7acf8e8807fe3fab991884d2208b7e03d35a409/cap-primitives/src/fs/open_dir.rs),
[Windows root-handle opens and opened-object checks](https://github.com/bytecodealliance/cap-std/blob/b7acf8e8807fe3fab991884d2208b7e03d35a409/cap-primitives/src/windows/fs/open_unchecked.rs),
[Windows directory sharing](https://github.com/bytecodealliance/cap-std/blob/b7acf8e8807fe3fab991884d2208b7e03d35a409/cap-primitives/src/windows/fs/dir_utils.rs),
and [pathname-based Windows rename](https://github.com/bytecodealliance/cap-std/blob/b7acf8e8807fe3fab991884d2208b7e03d35a409/cap-primitives/src/windows/fs/rename_unchecked.rs).
The archives use edition 2021 and do not declare a package MSRV. Compatibility
of their full resolved graph with Anvil's Rust 1.90 is not proved by inspection.
Application code introduces no unsafe code or lint exemption.
The direct safe `rustix` dependency is pinned to the already locked 1.1.5;
its downloaded archive hash matches the existing Cargo.lock checksum
`891efababe418670775f199f0d233d84843c227a0949a883ce15b37c78d6629d`.

`Cargo.lock` is intentionally unchanged, rather than inventing a dependency
graph locally. The narrowly scoped `file-handle-lock.yml` workflow runs only
on pushes to `fix/retained-file-and-export-handles`, checks out the exact push
SHA without persisted credentials, has only `contents: read`, uses no secrets
or caches, and resolves with Rust 1.90.0 on GitHub-hosted Linux. It executes no
project build scripts or tests and uploads the real lock, its SHA-256, exact
source SHA, run/attempt and toolchain provenance. It cannot write back to Git.
Root must download the artifact for the immutable pushed SHA, verify provenance
and hash, inspect the graph/MSRV/licenses/advisories, and apply it in the next
round. Existing `--locked` CI cannot qualify this branch until that handoff.

## Hosted proof plan and current evidence

No repository code, formatter, compiler, test or build system was executed
locally. Static source/diff inspection, archive/index integrity comparison and
`git diff --check` are the local evidence. The tests below have been written,
**not executed**. Root owns all-platform CI and independent security review.

The unit tests inject bounded two-way rendezvous barriers inside actual linked
dataset/request reads, native chooser handle acquisition and `FileGrants::write`.
They rename a real ancestor and redirect it through a POSIX symlink or native
Windows `mklink /J` junction. Junction tests do not silently skip Windows or
require the symbolic-link privilege. A Windows sharing violation is an allowed
protected-path outcome only; the unprotected controls require a real successful
swap and demonstrate scratch outside-canary disclosure/redirected creation.

Protected tests assert original selected bytes, unchanged outside files, no
created outside output or partial, and policy-consistent output in the retained
directory. Other tests cover chooser-time swaps, opened file ID replacement,
in-place edits, inert restart records, old lock epochs, occupied final-leaf
races, preserved foreign temporaries, and the explicit source-publish blocker.
Existing native PEM, purpose, TTL, size, FIFO, import/referrer and permission
tests remain relevant. Some positive tests explicitly adopt the **draft**
no-overwrite/reselection policy; they are not evidence of unchanged compatibility.
