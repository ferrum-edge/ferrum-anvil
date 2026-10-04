# Retained file and export handles — DRAFT

Owner decision: **root**. This branch is a review candidate, not an approved
compatibility change or a qualified fix. Do not close the advisory or claim a
patched release from this work. The accepted publication, revocation, dialog
and retirement defects have concrete source changes below; **all-platform
hosted qualification is still required**. macOS uses descriptor cloning rather
than rename and retains uncertain staging names; its support/retention contract
needs owner attention before integration. This round additionally restricts
macOS export destinations to audited local APFS mounts with ownership enabled.
That is a proposed filesystem compatibility change, **not owner approved**.

The assigned source base is `4254ea84c101bdc9231a4c6f455421e22468d0ec`.
[GHSA-6hc8-xjvq-478g](https://github.com/ferrum-edge/ferrum-anvil/security/advisories/GHSA-6hc8-xjvq-478g)
reports an ancestor rename followed by symlink/junction replacement between
canonicalization and a fresh pathname open/create. The advisory API was read in this round. It scopes the finding to reported
revision `b7aca6f46988dacdaec97f4d2a0af0f8fe238d7e`; neither that sealed snapshot
nor this static inspection establishes affected released binaries.

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

Referrer records, imports remaining inert, workspace checks, grant purpose,
token opacity, token bounds, TTL and PEM vault fencing stay in their services.
Only the native file chooser changes in the desktop shell. Linked deletion
hooks in App bundle import and backup restore retire committed selections;
shared native state, other native commands, HTTP, identity and transport
implementations are outside this change. `FileGrants`
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

Selection replacement revokes the removed selection under the registry
mutex, before it becomes invisible to lock. Relocation, bundle import and
backup restore carry that mutex guard through the successful database commit,
retire exactly the committed deleted bindings, and mark them revoked before
releasing the mutex. Rollback/refusal leaves existing authority intact. Native
file acquisition and descriptor closure occur outside that mutex; database
operations during these commits do run under it. Lock order is store transaction
then selection registry; the store is never acquired while holding the registry
alone. Old request contexts cannot regain removed authority after unlock.

The desktop captures an opaque linked-selection epoch before opening its
dialog, passes it through bind/relocate, and the issuer checks that exact epoch
under the registry mutex held through commit and selection publication. The
postcheck has a receipt for exactly its selected object: it revokes that object
and removes it only if it is still the registry entry, preserving a subsequent
choice. A stale dialog cannot adopt the newer generation after its precheck.

Each opened App session and each FileGrants registry has a **512-descriptor**
retention budget, independent of the token bound. Each retained root/component
directory and selected original file is charged before opening; export staging
also reserves a descriptor. The charge survives registry removal, revocation
and TTL expiry while an old context or in-flight operation retains the object,
and is released after actual descriptor closure. New acquisitions fail cleanly
when exhausted; no live authority is silently evicted by this budget. Temporary
metadata clones and reopened reads/procfs handles are short-lived I/O rather
than retained selections. This per-session bound does not cap all unrelated
process descriptors or an unlimited number of separately opened profiles.

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

Publication never resolves a checked temporary name again:

- **Linux:** `rustix::fs::openat` creates an unnamed `O_TMPFILE` in the
  retained parent. After write and file fsync, `linkat` publishes that owned
  descriptor to one unoccupied leaf. `AT_EMPTY_PATH` is attempted first;
  unprivileged callers use the documented `AT_SYMLINK_FOLLOW` link through
  kernel-owned `/proc/self/fd/<live-fd>`. `/proc` is opened no-follow and its
  filesystem type must be `PROC_SUPER_MAGIC`; an ordinary fake directory is
  refused. There is no mutable staging leaf for an attacker to replace, and
  no partial on success or failure. The filesystem must support `O_TMPFILE`
  and hard-link publication; the unprivileged path requires authentic procfs.
  No named-source rename fallback is used. This creates a link atomically;
  it is not a claim that an unnamed inode has undergone rename.
- **Windows:** the exclusively created staging file is opened with
  `GENERIC_READ | GENERIC_WRITE | DELETE` and only `FILE_SHARE_READ`. Other
  handles cannot write or delete/replace it while retained. Publication calls
  `SetFileInformationByHandle(FileRenameInfoEx)` on that exact handle with
  the retained destination directory as `RootDirectory`, a single UTF-16
  leaf, and flags **zero**. No replacement or POSIX-overwrite flag is set.
  Successful native rename consumes the source name; there is no hard-link
  fallback and no successful additional `.partial` link. Windows 10 RS1 or
  newer and filesystem support for this operation are required. Unsupported
  operations fail instead of falling back to an unsafe publication.
- **macOS:** an exclusively created, mode-0600 staging file is published
  by `rustix::fs::fclonefileat` from the retained descriptor into the retained
  destination directory. Apple documents atomic all-or-nothing creation,
  refusal of existing destinations, and a separate copy-on-write inode.
  XNU gets the source vnode from the descriptor (`fp_getfvp`), not its staging
  pathname. A foreign replacement/hard-link/symlink at that pathname is
  never published or treated as ours. The candidate requires the local APFS
  mount profile described below, and source/destination must share a volume.
  There is no name-based copy/rename fallback on unsupported volumes.

### macOS filesystem and mount policy — DRAFT, approval required

Before dispatching native staging creation, `file_publish` obtains `fstatfs`
from the **held destination directory descriptor**. The creating thread
rechecks that descriptor immediately before `openx_np`. `FileGrants::write`
rechecks before its first plaintext write; publication rechecks before
`fclonefileat`. Each query describes the retained directory's mount, including
after an ancestor rename. No pathname precheck, mode or owner metadata can
substitute for this policy. Failed policy checks create no staging entry;
checks after staging refuse further writes/cloning and retain the uncertain
source under the existing retention policy. There is no pathname cleanup in
this candidate. Any future cleanup needs a fresh held-directory policy check
and an independently safe object-removal primitive.

The allowlist requires the kernel filesystem name `apfs`, `MNT_LOCAL`, and
ownership enforcement. It rejects SMB, NFS, WebDAV, FUSE, HFS, exFAT, NTFS,
unknown or malformed type names, nonlocal mounts, `MNT_IGNORE_OWNERSHIP`,
read-only, union, exported, automounted, snapshot and deprecated volfs profiles.
HFS is deliberately excluded: the owned clone-publication contract has not
been qualified there. Only recognized flags for synchronization, execution,
setuid/device restrictions, content protection, removable storage, quarantine,
quota, root/data volume, browsing, journaling, xattrs, deferred writes, MAC
labels, no-follow and access-time policy are allowed. All other visible bits
fail closed. The extended field permits only `MNT_EXT_ROOT_DATA_VOL`; FSKit
and unknown extended bits fail closed. Root must qualify legitimate destination
profiles and approve this narrower support contract before integration.

Static ABI verification used the installed Apple MacOSX26.5 SDK's
`usr/include/sys/mount.h`, the
[XNU mount definitions](https://github.com/apple-oss-distributions/xnu/blob/main/bsd/sys/mount.h),
[XNU descriptor statfs implementation](https://github.com/apple-oss-distributions/xnu/blob/main/bsd/vfs/vfs_syscalls.c),
[locked libc 0.2.189 definitions](https://github.com/rust-lang/libc/blob/0.2.189/src/unix/bsd/apple/mod.rs),
and [rustix 1.1.5 native StatFs alias](https://github.com/bytecodealliance/rustix/blob/v1.1.5/src/backend/libc/fs/types.rs).
Darwin's `f_flags` and `f_flags_ext` are `uint32_t`; libc's `MNT_*` values are
`c_int`, converted by their explicit 32-bit representation. `f_type` is a
runtime VFS registration number, not a portable APFS magic number, so the
policy uses the kernel's NUL-terminated `f_fstypename`. The preserved Linux
procfs check uses the explicit fallible `libc::c_long` conversion from head
`375128d4d51d4467af6e83559078d7d608c41c3c`.

On ownership-enforcing local APFS, the candidate combines initial mode `0600`
with an explicit empty `ACL_FLAG_NO_INHERIT` ACL through `openx_np`. XNU
[prepares initial security attributes before native creation](https://github.com/apple-oss-distributions/xnu/blob/main/bsd/vfs/vfs_subr.c)
and [suppresses inheritance for that ACL](https://github.com/apple-oss-distributions/xnu/blob/main/bsd/kern/kern_authorization.c).
The source descriptor must retain an empty non-inheriting ACL before writing
and cloning; `CLONE_ACL` carries that policy into destination creation. These
contracts require real hosted APFS qualification. A later ACL postcheck does
**not** revoke a foreign handle already opened during unsafe creation. Mode
`0600`, reported UID and empty ACL do **not** establish effective ownership on
[Ignore Ownership volumes](https://support.apple.com/en-om/guide/mac-help/mchlp1204/mac).
In particular, [Apple SMB creation](https://github.com/apple-oss-distributions/SMBClient/blob/main/kernel/smbfs/smbfs_vnops.c)
applies some security attributes after creation; this candidate rejects SMB
before creation and does not claim to qualify its handle access semantics.

Retaining a directory descriptor does not freeze mount policy. All checks
assume ownership enforcement and the audited native filesystem implementation
remain stable throughout creation, writing, cloning and retained staging-data
lifetime. An actor able to remount, toggle ownership, replace a filesystem
implementation or administer an image can change policy between checks or
after success. Such administrative authority is outside this contract;
rechecks only detect changes already visible when queried. No atomic mount
policy lease or retroactive access revocation is claimed. Existing named
staging data remains subject to this limitation even after export completion.

This is a local destination-filesystem policy in `FileGrants`; it does not
change HTTP/HTTPS request access, remote API authorization, TLS, linked-file
read authorization or the application identity policy.

The existing real macOS inherited-ACL regression uses a separately authorized
native `nobody` account, a readable inherited-ACL control, and denied reads of
both staging and final exports before and after directory ACL changes. New
synthetic profiles exercise the production `fstatfs` policy seam before native
creation, before plaintext and before cloning. Unsupported names and every
unsupported visible/extended flag bit are covered. These are rejection tests,
**not real SMB/NFS qualification**.

The optional [hosted macOS qualification workflow](../../.github/workflows/macos-file-policy.yml)
checks out the exact source SHA with a fully pinned action, read-only permission,
no persisted credentials, no shared caches and no repository write-back. It
creates its own APFS image under a private runner-temp path and attaches that
image with `-owners off`. The ignored native test requires the GitHub-hosted
environment and observes real APFS, LOCAL and IGNORE_OWNERSHIP descriptor fields
before requiring rejection without staging. The workflow also runs the real
inherited-ACL test and synthetic controls. An EXIT/signal cleanup trap is
installed before image creation, identifies only this exact image path,
detaches its owned device, removes the fixture only after successful detach,
and reports the private mount path, source SHA and cleanup status. Existing
runner/user volumes are never reconfigured. Forced runner destruction can
interrupt cleanup; cancelled runs require explicit cleanup evidence and are
not accepted as qualification.

**Current evidence:** source/SDK inspection only; no new regression or image
workflow has run in this implementation session. Root must inspect the new
hosted run's test results and cleanup record, plus all-platform CI and a fresh
independent security/workflow review. If APFS image attachment or the native
Ignore Ownership assertion fails, the actionable human step is to run this
workflow on an authorized GitHub-hosted macOS runner at the pushed source SHA,
record `hdiutil` output, native descriptor flags and the private path, and require
`cleanup_status=0`. Do not change a user's existing drive to obtain evidence or
substitute a synthetic profile for the native flag assertion. Owner approval
comes only after this candidate is fully qualified and reviewable; this document
does not declare the advisory resolved or integration externally blocked.

**macOS staging-retention constraint:** the public API audited here has no
unlink-by-descriptor operation. A pathname identity check followed by unlink
would again risk deleting a foreign replacement. This candidate therefore
preserves the uncertain named staging entry on success and failure, including
its mode-0600 export data. The clone is an independent inode; this is not the
removed Windows extra-output-link bug. Root must qualify/replace this concrete
retention policy, or supply an independently reviewed staging authority model.
Random names and mode 0700 alone do not prove a namespace inaccessible to a
same-user actor. Windows may also retain its own staging entry on failure; it
never cleans up a pathname whose ownership is uncertain.

No uncertain final name is rolled back or unlinked. Native publication itself
refuses a destination planted after the optimistic precheck. No post-publication
identity check is used as authorization or as an attempted repair after moving
a foreign source. A concurrent attacker can still change their writable
namespace after our publication; this does not authorize the application to
follow or overwrite that entry. File-only fsync does not claim parent-directory
power-loss durability or macOS clone-metadata durability.

Primary native API evidence, inspected as data without local execution:
[Linux O_TMPFILE and fd-link publication](https://man7.org/linux/man-pages/man2/open.2.html),
[Linux linkat semantics](https://man7.org/linux/man-pages/man2/link.2.html),
[rustix 1.1.5 safe at APIs](https://github.com/bytecodealliance/rustix/blob/v1.1.5/src/fs/at.rs),
[Apple clonefile contract](https://github.com/apple-oss-distributions/xnu/blob/main/bsd/man/man2/clonefile.2),
[XNU fclonefileat source-vnode acquisition](https://github.com/apple-oss-distributions/xnu/blob/main/bsd/vfs/vfs_syscalls.c),
[Windows FILE_RENAME_INFO root/flags](https://learn.microsoft.com/en-us/windows/win32/api/winbase/ns-winbase-file_rename_info),
[Windows rename requirements and no-replace semantics](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/ns-ntifs-_file_rename_information),
[Windows SDK information-class enum](https://github.com/microsoft/win32metadata/blob/main/generation/WinSDK/RecompiledIdlHeaders/um/minwinbase.h).

The source namespace proof assumes the kernel, this process/descriptor table,
and its mount namespace are trusted. The advisory's actor may replace selected
ancestor and leaf entries, including as the same user, but cannot change
kernel-owned procfs fd links, inject/close our live descriptor, or administer
our mount namespace. Such process/mount control invalidates this model and
requires stronger process isolation. Native directory authority does not make
selected writable file contents immutable against an actor who can directly
write them. The Windows FFI boundary is narrowly isolated with `allow(unsafe_code)`:
C layout, buffer alignment/length, live borrowed handles, UTF-16 leaf validation
and synchronous buffer lifetime are explained at the call site. Its ABI and
runtime behavior remain all-platform hosted qualification requirements.

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
The isolated Windows publication and Darwin ACL/filesec boundaries use unsafe
code with their specific ABI/lifetime justifications. Descriptor filesystem
queries and the remaining native filesystem calls use safe published APIs.
The direct safe `rustix` dependency is pinned to the already locked 1.1.5;
its downloaded archive hash matches the existing Cargo.lock checksum
`891efababe418670775f199f0d233d84843c227a0949a883ce15b37c78d6629d`.

Root already applied the genuine hosted artifact in commit
`b0e563049f021db8a17eff7f5c9c983ed1c81f72` (110 additions). This round preserves
that complete lock graph and every existing pin without changes. The current
lock SHA-256 is `f13b887c98c44bfbad98c823c9b3db39353e0f692df7274bcd0d34b1a7de8b49`.
No dependency is added by this round, and no local resolver or hand-built lock
is used. The dedicated hosted workflow remains available for real dependency
changes; it has no repository write permission or persisted credentials.

## Hosted proof plan and current evidence

No repository code, formatter, compiler, test or build system was executed
locally. Static source/diff inspection, archive/index integrity comparison and
`git diff --check` are the local evidence. New/changed regressions below have been written,
**not executed in this round**. Root owns all-platform CI and independent security review.

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
races, outside-canary hard links injected as source/destination, descriptor
budgets, 60 relocations with constant registry/descriptor use, old contexts
across replacement plus lock/unlock, committed import/restore retirement and
rollback/refusal preservation. Actual desktop bind/relocate regressions pause
after the precheck and after binding, lock/unlock, prove no usable grant remains,
and exercise a fresh positive choice. Existing native PEM, purpose, TTL, size, FIFO, import/referrer and permission
tests remain relevant. Some positive tests explicitly adopt the **draft**
no-overwrite/reselection policy; they are not evidence of unchanged compatibility.

Current prior-head hosted evidence was read, rather than repeating the obsolete
missing-lock diagnosis. CI run `37201183351` at b0 failed Linux formatting in
`exec.rs`, `file_grants.rs`, and `file_handle_tests.rs` (the printed edits are
applied here). macOS compiled and reached tests, failing the linked-dataset
positive fixture at `tests/local_files.rs:634`; its non-CSV canary fixture is
changed to valid CSV here. Supply-chain cargo-deny passed; the generated
`THIRD_PARTY_LICENSES.md` check failed as stale. Lab and desktop E2E passed at b0.
These prior-head results do not validate the new native operations, FFI,
concurrency regressions or formatter changes. Root owns the pushed candidate's
Linux/macOS/Windows gates, hosted license regeneration outside this worker's
file scope, and compatibility/retention decisions. No fix is declared qualified.
