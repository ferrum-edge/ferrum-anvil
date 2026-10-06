# Workspace owner binding

Status: **implemented storage controls.** This is not a claim about affected
or patched released binaries.

## Implemented controls

The released `anvil/v1/objects/<kind>/<id>` AAD and schema version 2 are
unchanged: that AAD authenticates the table, kind and row ID. Every
workspace-scoped object's encrypted JSON also carries an ID and owner, except
request revisions. Before returning an object, storage compares those sealed
fields to the actual row metadata, including for `serde_json::Value` reads and
unscoped lists. No row is resealed, repaired, adopted or assigned an owner at
open/unlock.

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
| Request revision | Embedded revision ID and request ID |

Domain kinds are decoded as their declared domain type before data is
returned. For app-owned kinds, storage decodes their identity projection
without introducing a storage-to-app dependency. Unknown kinds fail closed.
Ordering and timestamps remain unauthenticated metadata; inventory APIs still
expose metadata for cleanup and corruption reporting, and must not be used as
payload authorization.

`Store::put` takes an immediate write transaction; `StoreTx::put` uses its
existing one. Each validates the submitted identity, opens and validates any
existing row, and rejects an existing owner's change before sealing or updating
any column. A new workspace-scoped object requires an existing, validated
workspace in the same transaction. An edited index cannot be legitimized by
resubmitting an object with that index's owner. Object reads use one consistent
transaction, including revision-to-request lookups.

Folder create/save validates the workspace and parent inside its write. Request
saves reject a changed owner or another request's revision, while retaining a
stored request's placement after a concurrent explicit move. Explicit
folder/request moves keep their owner and existing transactional relationship
checks. A new request is written before its first revision in the same
transaction; deletion reads revisions before removing their parent. Reimport
writes a revision only for a changed request present in the transaction's
checked previous set.

## Orphan revisions and retention

Released profiles can already contain revisions whose request was deleted.
Ordinary typed/untyped gets and scoped/unscoped lists still refuse them. Full
profile backups exclude each authentic orphan revision with an explicit
manifest entry and count only included revisions, carrying its available
attachment bytes through the profile-wide attachment index. The original
encrypted row remains in the profile and any existing checkpoints; the portable
backup does not carry that ciphertext or its spec. Keep a profile checkpoint if
recovering the excluded history is required. Attachment bytes without an
ordinary saved referrer remain retained after portable restore; that is not a
trust decision to adopt the excluded history or delete its files. No backup
read creates quarantine rows, adopts owners or reseals data. A malformed or
undecryptable revision still fails the backup, rather than being silently
omitted.

The internal `StoreRead::orphan_revision_attachment_refs_for_retention`
inspection authenticates the released kind/ID envelope, checks the decoded
revision ID, and checks absence of the **sealed** request ID in the same read
transaction. An existing request, including a corrupt one, is never treated as
missing. It returns only canonical attachment hashes, never a spec, URL, file
name, workspace owner or executable request context. Its only callers are
profile backup exclusion and profile-wide reference retention.

Cleanup gathers those hashes before deleting an orphan and releases its files
only after the ordinary cross-profile reference scan finds no other holder and
the attachment grace period permits release, including imported attachment
indexes with `user: false`. If any revision's references cannot be inspected,
its row and pins remain and the pass removes/releases nothing. Request deletion
keeps undecodable revision rows for a later safe cleanup. Workspace deletion
reads live revisions before their parents disappear and keeps
orphan/undecodable revisions for profile-wide cleanup.
