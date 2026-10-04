# Workspace owner binding candidate

Status: **draft implementation and owner decision required**. References
GHSA-fmx8-p5wc-hm8p. The inspected baseline is
`4254ea84c101bdc9231a4c6f455421e22468d0ec`. This is not a published fix or a
claim about affected or patched released binaries.

## Compatible controls implemented

The released `anvil/v1/objects/<kind>/<id>` AAD and schema version 2 stay
unchanged. That AAD already authenticates the table, kind and row ID. The
encrypted JSON already carries an ID and owner for every workspace-scoped
object **except request revisions**. The candidate compares those sealed
fields to the actual row metadata before returning an object, including
when the caller requests `serde_json::Value` or lists all workspaces.

This is validation of authenticated plaintext, not a claim that the SQLite
owner column is part of the existing AAD. No row is resealed, repaired,
adopted or assigned an owner at open/unlock.

| Kind | Authenticated identity checked against the row |
| --- | --- |
| Workspace | Flattened metadata ID; workspace and parent indexes must be null |
| Folder | Flattened metadata ID, workspace ID, optional parent folder ID |
| Request | Flattened metadata ID, workspace ID, optional folder ID |
| Environment, dataset, scenario | Flattened metadata ID and workspace ID; parent index must be null |
| TLS, proxy, integration, load plan | ID and workspace ID; parent index must be null |
| Collection run report | Run ID and workspace ID; parent index must be null |
| Spec provenance | Source import ID and workspace ID; parent index must be null |
| Device identity seal | Workspace ID is both the object ID and owner; parent index must be null |
| User profile, API ruleset | Embedded ID; workspace and parent indexes must be null |
| App settings, attachment index | Kind/ID in existing AAD; fixed profile-only scope, with null workspace and parent indexes |
| Token/linked file binding | Embedded ID; fixed profile-only scope, with null workspace and parent indexes |
| Request revision | Embedded revision ID and request ID; see the unresolved limitation below |

Domain kinds are decoded as their declared domain type before returning
data, regardless of the caller's output type. For app-owned kinds, storage
decodes their identity projection without introducing a storage-to-app
dependency. Unknown kinds fail closed. Ordering and timestamps remain
unauthenticated metadata; inventory APIs still expose metadata for cleanup
and corruption reporting, and must not be used as payload authorization.

`Store::put` takes an immediate write transaction. `StoreTx::put` uses its
existing transaction. Each validates the submitted identity, opens and
validates an existing row, and rejects an existing owner's change before
sealing or updating any column. A new workspace-scoped object requires an
existing, validated workspace in the same transaction. An edited index
cannot be legitimized by resubmitting an object with that index's owner.
Object reads use one consistent transaction, including revision-to-request
lookups, so another connection cannot change the parent between checks.

These store guards cover the App saves used by desktop environment, TLS,
proxy, integration, dataset, scenario and load-plan commands without
changing desktop IPC files or execution code. Workspace and folder settings
travel inside their validated owners; app settings remain profile-wide.
Existing secret v2 AAD and workspace-qualified secret lookups are unchanged.

Folder creation/save validates the workspace and parent together with its
write. Request saves explicitly reject a changed owner or another request's
revision, while retaining a stored request's placement after a concurrent
explicit move. Explicit folder/request moves keep their owner and existing
transactional relationship checks. A new request is written before its
first revision in the same transaction; deletion reads revisions before
removing their parent, so owner validation and attachment release continue
to work through the production methods.

## Unresolved revision ownership: owner decision required

The released `RequestRevision` JSON contains `id`, `request_id`, timestamp,
hash and spec, **but no workspace ID**. The candidate checks the revision's
sealed request ID against `parent_id` and compares the row's owner with the
current parent request's validated sealed owner. A missing or corrupt parent
fails closed. This prevents a direct metadata-only reassignment while the
original parent still exists, but it is not proof of the revision's original
workspace.

In particular, an old authentic revision ciphertext can survive outside the
database. If its original request is deleted and the same request ID is
later created under another workspace (for example by an import), restoring
the old revision ciphertext with that workspace's plaintext owner column
can pass the current-parent check. No DEK is needed to restore those bytes.
The original owner cannot be recovered cryptographically from that revision.
An orphan's owner column or a newly recreated parent's owner is not an
authenticated historical owner. No immutable ownership tombstone currently
exists outside the attacker-editable database.

Therefore the candidate is **not a complete remediation of the advisory**.
It deliberately does not invent an ownership proof, automatically upgrade
legacy revisions, or change released profile semantics. Other object kinds
have their own sealed owner (or a fixed profile-only scope) and do not rely
on this historical-parent assumption. A general database rollback remains
outside the guarantee as already documented in storage-and-recovery.

### Concrete proposed format and migration

The following requires owner approval before implementation:

1. Introduce a schema version 3 revision representation with an explicit
   encrypted `workspace_id`. Bind revision ID, workspace ID, request ID and
   a format discriminator in new, unambiguous length-prefixed AAD. Continue
   checking the decoded identity, metadata and parent relationship. Keep
   existing independently verifiable object kinds in their released format.
2. New revisions derive their owner from the parent loaded in the same write
   transaction. Writes and reads reject mismatched sealed/index ownership;
   owner and revision parent remain immutable on updates. Older builds must
   refuse schema 3. Version setback must not enable a fallback writer that
   silently mixes old and new revision formats.
3. Opening a legacy profile must not bulk-reseal its revisions using SQLite
   owner/parent columns. Preserve their bytes in quarantine, with no routing,
   replay or revision-spec consumption. Identify legacy rows in a migration
   preview, report that their historical owner is unverifiable, and retain a
   recoverable checkpoint before any approved write. Orphans cannot use a
   current-parent explanation at all.
4. The owner must choose a recovery policy: discard/quarantine legacy revision
   history and create fresh revisions from the independently authenticated
   current requests, or explicitly trust a separately authenticated,
   known-clean backup or a reviewed mapping of legacy rows. A user-approved
   mapping is a new trust decision, not cryptographic verification of the
   old owner. Merely unlocking with the DEK supplies no such decision.
5. Apply an approved mapping atomically and record its exact trust source and
   scope in the migration result. An interrupted or refused migration leaves
   legacy ciphertext intact and does not change owners or adopt rows in the
   background. Define restore/import behavior for both legacy and new
   revisions, including stale ciphertext replay after parent-ID reuse,
   before enabling writes of the new representation.

No migration, lifecycle ceremony, new AAD or schema bump is included here.
This plan needs coordination with the owners of profile/vault lifecycle and
backup/import code, which are outside this assignment's edit scope.

## Validation evidence and limits

Added tests exercise production Store SQL and App methods:

- Every declared object kind plus the three device-specific kinds: valid
  creation/update; direct and transactional cross-owner refusal; SQLite-only
  owner, ID, kind and parent tampering; scoped and unscoped lists and gets;
  rejected new creates leave no partial row.
- Already sealed invalid IDs, embedded owners, types and revision parents
  are refused before a normal save can reseal them.
- Renderer-reachable App saves reject existing cross-owner IDs; metadata-only
  edits are refused by App lists/saves; ciphertext and all row metadata stay
  unchanged on rejection.
- Explicit same-workspace folder/request moves remain supported; foreign,
  missing and cyclic targets leave no row mutation; a stale request save
  keeps its authorized move. A failing final request write rolls back the
  new revision, and another request's revision is rejected.

Existing storage concurrency/security fixtures now provide actual domain
identities rather than partial workspace JSON. No tests, project tooling,
builds or formatters were run locally. `git diff --check` and static review
are the local checks; GitHub-hosted CI is the execution gate. Hosted results
must be assessed independently before any merge or claim of a verified fix.
The tests of revision parent checks do not establish the missing historical
owner invariant; the proposed format needs an additional replay-after-reuse
regression that requires rejection through the production store.
