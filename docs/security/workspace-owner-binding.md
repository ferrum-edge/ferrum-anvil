# Workspace owner binding

Status: **implemented storage controls.** This is not a claim about affected
or patched released binaries.

## Implemented controls

The released `anvil/v1/objects/<kind>/<id>` AAD is unchanged for every kind
except request revisions: it authenticates the table, kind and row ID. Every
workspace-scoped object's encrypted JSON also carries an ID and owner. Request
revisions are sealed by database schema 3 under their own AAD, with the
workspace and request that own them inside the encrypted payload
([below](#request-revisions)). Before returning an object, storage compares
the sealed fields to the actual row metadata, including for
`serde_json::Value` reads and unscoped lists. Apart from the one-time schema 3
step for revisions and history records, no row is resealed, repaired, adopted
or assigned an owner at open/unlock.

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
| Request revision | Revision ID (schema 3 AAD); sealed workspace and request ID, and the embedded revision and request ID; the request must still authenticate in that workspace |

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

## Request revisions

A revision's own type has no workspace field, so schema 3 seals it inside an
envelope: `{workspace_id, request_id, revision}` under the AAD
`anvil/v3/objects/revision/<len>:<id>`. A read requires the sealed workspace
and request to equal the row's owner and parent columns, the embedded revision
to name the same ID and request, and that request to authenticate today with
the same workspace. The sealed owner is historical, so a revision of a request
that was deleted and whose ID was later reused in another workspace is refused
whichever owner column it is put back under, and the current-request check
refuses it even under its original owner. A schema 1 revision ciphertext no
longer opens for any ordinary read.

The schema 3 migration runs once, at open, unlock or checkpoint restore, in
one write transaction with the version bump. It seals a revision only if the
schema 2 read accepted it: it decrypts under the schema 1 AAD, its embedded ID
and request match the row, and that request authenticates with the revision's
owner column as its sealed workspace. The owner therefore comes from the
authenticated request. Every other revision (orphaned, under a request that
does not decrypt or whose owner was edited, or filed under another workspace
or request) is left byte for byte as it was and counted in
`meta.revisions_left_at_v3`. It stays refused, as it already was, and is never
adopted later, even after its request or columns are repaired. A database
whose recorded version is below 3 while a revision opens under the schema 3
AAD was set back; the step fails without writing, and a checkpoint like that
is refused before the live database is touched.

## History records and load reports

An execution record seals its workspace and request ID; a load report seals
its plan's workspace. Every read path compares them with the row's plaintext
columns and refuses a mismatch: `get_history`, `list_history` and
`history_entries`, `get_load_report`, `list_load_reports` and
`load_report_entries`. Owner maps used by import and restore conflict checks
therefore come from the sealed owner too.

A history record's response body is stored as a separate blob, and the row
names it in a plaintext `body_blob` column. Schema 3 seals the record under
the AAD `anvil/v3/history/record/<len>:<id>/body/<len>:<blob id>` (or
`.../no-body` for a record without one), so the record opens only with the
body column it was written with. A blob ID is a keyed hash of the blob's
content and a blob opens only under its own ID, so a record whose body column
is pointed at another blob, or cleared, is refused instead of returning that
blob. Load reports keep their released AAD (table, kind, ID).

The schema 3 step seals each existing history record again, once, with the
body column its row has then, as revisions take their request's owner once.
Only a record the schema 2 read accepted is sealed: it decrypts under the
schema 1 AAD and its sealed workspace and request equal its columns. Any other
record is left byte for byte, counted in `meta.history_left_at_v3`, and stays
refused until it is deleted. A record that already opens under its schema 3
AAD in a database whose recorded version is below 3 means the version was set
back; the step fails without writing, and a checkpoint like that is refused.

A write must index a record or report under the owner it seals. When a row
with the same ID already exists, the write first authenticates it and fails
with `Ownership` if it seals another workspace (or, for a history record,
another request), as an object update does; an existing row that does not
authenticate fails the write too. A profile-wide listing that meets a record
or report that fails these checks names its ID in the error, so it can be
found and deleted. Retention, clearing and workspace deletion still select
rows by their plaintext columns; an edited column can make such a row be
deleted with another workspace's, but never read under it.

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
inspection authenticates the revision's schema 3 envelope (or, for a revision
the schema 3 migration left as it was, the released kind/ID envelope), checks
the decoded revision ID and, for schema 3, that the envelope and revision name
the same request, and checks absence of the **sealed** request ID in the same
read transaction. An existing request, including a corrupt one, is never
treated as missing. It returns only canonical attachment hashes, never a spec,
URL, file name, workspace owner or executable request context. Its only callers are
profile backup exclusion and profile-wide reference retention.

Cleanup gathers those hashes before deleting an orphan and releases its files
only after the ordinary cross-profile reference scan finds no other holder and
the attachment grace period permits release, including imported attachment
indexes with `user: false`. If any revision's references cannot be inspected,
its row and pins remain and the pass removes/releases nothing. Request deletion
keeps undecodable revision rows for a later safe cleanup. Workspace deletion
reads live revisions before their parents disappear and keeps
orphan/undecodable revisions for profile-wide cleanup.
