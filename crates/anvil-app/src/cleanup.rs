//! Storage cleanup when a profile opens: revisions and stored files that no
//! saved item can reach any more are removed. A file any saved item of any
//! workspace references is never released.

use crate::workspace::{
    AttachmentIndex, REFERRERS, attached_recently, attachment_entries_in, attachment_index_id, drop_attachment_in, grace_cutoff,
    reference_scan_in,
};
use crate::{App, AppError, Result};
use anvil_domain::Id;
use anvil_storage::{StoreError, StoreRead, StoreTx, kind};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashSet;
use std::time::Duration;

/// How long a file a user attached ([`App::put_attachment`]) waits for a
/// saved item to reference it. Once it is older and no saved item does, the
/// cleanup at profile open releases it. Attaching the same content again
/// restarts the wait, and a save that names a released file is refused
/// ("attach it again"), so no saved item names content that is gone.
pub const ATTACHMENT_GRACE: Duration = Duration::from_secs(30 * 24 * 60 * 60);

/// How often opening a profile runs the cleanup at most
/// ([`App::clean_up_storage_if_due`]).
pub const CLEANUP_INTERVAL: Duration = Duration::from_secs(24 * 60 * 60);

/// How many times a pass reads again when the store changed between its
/// read and its writes, before it gives up until the next one.
const ATTEMPTS: usize = 3;

/// The store note ([`StoreRead::note`]) that keeps the last pass.
const LAST_PASS_NOTE: &str = "storage_cleanup";

/// Why a revision that a newer Anvil may have written is not removed.
const NEWER_FORMAT: &str = "was written by a newer Anvil, or in a format this version cannot read: it is kept for that version";

/// Why a revision that decodes is not removed.
const DECODES: &str = "decodes; only a damaged revision, which nothing can read, can be removed here";

/// What one cleanup pass did.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct StorageCleanup {
    /// Revisions removed because the request they belong to no longer exists.
    pub orphaned_revisions: usize,
    /// Stored files released: named only by the removed revisions, or
    /// attached longer than [`ATTACHMENT_GRACE`] ago and never saved.
    pub released_attachments: usize,
    /// Stored objects that did not decode while the pass checked what
    /// references its candidates. Each could name any stored file, so while
    /// one is left the pass removes and releases nothing. Each is also
    /// logged as a warning.
    pub undecodable: Vec<UndecodableObject>,
}

/// A stored object that does not decode, by kind and id (never content).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UndecodableObject {
    pub kind: String,
    pub id: String,
}

/// A stored revision whose own sealed payload does not decode
/// ([`App::undecodable_revisions`]). Nothing of its content is known.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UndecodableRevision {
    pub id: String,
    /// When its row was last written, in milliseconds since the Unix epoch.
    pub updated_at: i64,
    pub cause: Undecodable,
}

/// Why a stored revision does not decode.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Undecodable {
    /// Its sealed payload does not authenticate under this profile's key:
    /// it was damaged, and no version of Anvil can read it. Only such a revision can be removed
    /// ([`App::remove_undecodable_revisions`]).
    Damaged,
    /// Its sealed payload authenticates, so this profile wrote it, but this
    /// version cannot read what it holds: a newer Anvil may have written it.
    /// It is kept, for that version to read.
    UnknownFormat,
}

/// What [`App::remove_undecodable_revisions`] did.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RemovedRevisions {
    /// The ids of the revisions removed.
    pub removed: Vec<String>,
    /// The file name of the one checkpoint taken just before the removal (in
    /// the profile's `checkpoints` folder): the removed rows are kept there.
    pub checkpoint: String,
}

/// The last cleanup pass that ran on a profile ([`App::last_storage_cleanup`]).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StorageCleanupRecord {
    /// When it ran.
    pub ran_at: DateTime<Utc>,
    /// What it did.
    pub result: StorageCleanup,
}

/// [`StorageCleanupRecord`] as the store keeps it.
#[derive(Serialize, Deserialize)]
struct KeptPass {
    #[serde(flatten)]
    record: StorageCleanupRecord,
    /// When an object did not decode: the digest of the rows the pass read
    /// ([`rows_digest_in`]). Until they change, a pass finds the same.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    rows: Option<String>,
    /// When the pass left no orphaned revision: the digest of the revision
    /// and request rows it left ([`revision_rows_digest_in`]). Until they
    /// change, no revision can have lost its request, so a pass decrypts
    /// none to look for orphans.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    settled: Option<String>,
}

/// What a pass decided from one consistent read of the store.
struct Plan {
    /// Revisions filed under a request that no longer exists.
    orphans: Vec<Id>,
    /// Stored files no saved item references: named only by the orphans, or
    /// attached and never saved past the grace period.
    unreferenced: HashSet<String>,
    /// Files attached past the grace period that a saved item references:
    /// their mark is dropped.
    held: Vec<AttachmentIndex>,
    /// Files marked as attached with no time (marked before the time was
    /// recorded): the pass records its own time, so they age from it.
    unstamped: Vec<AttachmentIndex>,
    undecodable: Vec<UndecodableObject>,
    rows: String,
}

impl App {
    /// Remove the revisions of requests that no longer exist (builds before
    /// deletes removed them left them behind) and release the stored files
    /// that only they named, and the files a user attached longer than
    /// [`ATTACHMENT_GRACE`] ago that no saved item references. A file a user
    /// attached more recently is kept either way: re-attaching restarts the
    /// wait.
    ///
    /// What references a file is read in a read transaction, which never
    /// takes the write lock; the removals then run in a short write
    /// transaction only if nothing was written in between (see
    /// [`ChangeMarker`](anvil_storage::store::ChangeMarker)), and otherwise
    /// the pass reads again. Each pass authenticates revisions to classify
    /// orphans without trusting their indexes; other referrers are decoded
    /// when there are attachment candidates to release. The pass is kept
    /// ([`App::last_storage_cleanup`]).
    pub fn clean_up_storage(&self) -> Result<StorageCleanup> {
        self.clean_up_storage_between_phases(|| {})
    }

    /// [`App::clean_up_storage`], calling `between` after each read and
    /// before its write transaction, so a test can write where another
    /// connection could. Not for other callers.
    #[doc(hidden)]
    pub fn clean_up_storage_between_phases(&self, mut between: impl FnMut()) -> Result<StorageCleanup> {
        let cutoff = grace_cutoff();
        for _ in 0..ATTEMPTS {
            let (marker, plan) = self.store.read_consistently(|s| Ok((s.change_marker()?, plan_in(s, cutoff)?)))?;
            between();
            let done = self.store.atomically(|s| {
                // A write since the read could reference a file the plan
                // releases: read again.
                if s.as_read().change_marker()? != marker {
                    return Ok(None);
                }
                apply_in(s, plan).map(Some)
            })?;
            if let Some(done) = done {
                return Ok(done);
            }
        }
        Err(AppError::Invalid("the profile kept changing while its storage was cleaned up; the cleanup runs again later".into()))
    }

    /// [`App::clean_up_storage`] once [`CLEANUP_INTERVAL`] has passed since
    /// the last pass, unless that pass found an object that does not decode
    /// and nothing it read has changed since: it would find the same, and
    /// release nothing. `None` when no pass ran.
    pub fn clean_up_storage_if_due(&self) -> Result<Option<StorageCleanup>> {
        let now = Utc::now();
        let due = self.store.read_consistently(|s| {
            let Some(last) = kept_in(s)? else { return Ok(true) };
            let since = now.signed_duration_since(last.record.ran_at).num_milliseconds();
            // A pass recorded later than now (the clock was set back) does
            // not hold off the next one.
            if (0..CLEANUP_INTERVAL.as_millis() as i64).contains(&since) {
                return Ok(false);
            }
            match last.rows {
                Some(rows) => Ok(rows != rows_digest_in(s)?),
                None => Ok(true),
            }
        })?;
        if !due {
            return Ok(None);
        }
        self.clean_up_storage().map(Some)
    }

    /// The last cleanup pass of this profile, if one ran: when, what it
    /// removed, and the stored objects that did not decode, which keep every
    /// stored file until they are repaired or deleted.
    pub fn last_storage_cleanup(&self) -> Result<Option<StorageCleanupRecord>> {
        Ok(self.store.read_consistently(kept_in)?.map(|k| k.record))
    }

    /// The stored revisions whose own sealed payload does not decode, oldest
    /// write first. Each could name any stored file, so while one is left the
    /// storage cleanup releases nothing, and deleting its request or
    /// workspace keeps it. [`App::remove_undecodable_revisions`] removes
    /// the damaged ones.
    pub fn undecodable_revisions(&self) -> Result<Vec<UndecodableRevision>> {
        let mut found = self.store.read_consistently(|s| {
            let mut found = Vec::new();
            for m in s.object_meta(kind::REVISION)? {
                // A row whose id does not parse cannot be removed by id.
                let Ok(id) = m.id.parse::<Id>() else { continue };
                if let Some(cause) = revision_undecodable_in(s, &id)? {
                    found.push(UndecodableRevision { id: m.id, updated_at: m.updated_at, cause });
                }
            }
            Ok(found)
        })?;
        found.sort_by(|a, b| a.updated_at.cmp(&b.updated_at).then_with(|| a.id.cmp(&b.id)));
        Ok(found)
    }

    /// Refuse, unless every revision of `ids` is stored and damaged
    /// ([`Undecodable::Damaged`]): what [`App::remove_undecodable_revisions`]
    /// checks first. Lets a caller ask the user only about a removal that
    /// would go ahead.
    pub fn check_removable_revisions(&self, ids: &[Id]) -> Result<()> {
        if ids.is_empty() {
            return Err(AppError::Invalid("no revision to remove".into()));
        }
        let refused = self.store.read_consistently(|s| {
            let stored: HashSet<String> = s.object_meta(kind::REVISION)?.into_iter().map(|m| m.id).collect();
            for id in ids {
                if !stored.contains(&id.to_string()) {
                    return Err(StoreError::NotFound(format!("revision {id}")));
                }
                match revision_undecodable_in(s, id)? {
                    Some(Undecodable::Damaged) => {}
                    Some(Undecodable::UnknownFormat) => return Ok(Some(format!("revision {id} {NEWER_FORMAT}"))),
                    None => return Ok(Some(format!("revision {id} {DECODES}"))),
                }
            }
            Ok(None)
        })?;
        refused.map_or(Ok(()), |why| Err(AppError::Invalid(why)))
    }

    /// Remove the revisions `ids`, only while each is damaged: its own sealed
    /// payload does not authenticate, so nothing can read it, and while it is
    /// kept the storage cleanup releases nothing. One that decodes, or that
    /// a newer Anvil may have written ([`Undecodable::UnknownFormat`]), is
    /// refused, and then none is removed. One checkpoint of the profile is
    /// taken first, so the rows stay recoverable there; the stored files they
    /// may have named are then released by a later cleanup once nothing else
    /// holds them.
    pub fn remove_undecodable_revisions(&self, ids: &[Id]) -> Result<RemovedRevisions> {
        self.check_removable_revisions(ids)?;
        let checkpoint = self.store.checkpoint("before-removing-revisions")?;
        let removed = self.store.atomically(|s| {
            let mut removed = Vec::new();
            for id in ids {
                // Repaired (a checkpoint restore) or removed since it was
                // checked: kept, or already gone.
                if revision_undecodable_in(&s.as_read(), id)? == Some(Undecodable::Damaged) && s.delete(kind::REVISION, id)? {
                    removed.push(id.to_string());
                }
            }
            Ok(removed)
        })?;
        if removed.is_empty() {
            return Err(AppError::Invalid("the revisions changed since they were checked; none was removed".into()));
        }
        for id in &removed {
            tracing::warn!(kind = kind::REVISION, %id, "removed a damaged stored revision; a checkpoint keeps it");
        }
        let checkpoint = checkpoint.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default();
        Ok(RemovedRevisions { removed, checkpoint })
    }

    /// [`App::clean_up_storage_if_due`] when a profile opens. A failure does
    /// not stop the profile opening: it is logged, and a later open tries
    /// again.
    pub(crate) fn clean_up_storage_on_open(&self) {
        if let Err(e) = self.clean_up_storage_if_due() {
            tracing::warn!(error = %e, "storage cleanup did not finish; it runs again when the profile next opens");
        }
    }
}

/// Why revision `id`'s own sealed payload does not decode, as the cleanup
/// reads it to tell orphans (`StoreRead::orphan_revision_attachment_refs_for_retention`),
/// or `None` when it decodes: its request is not consulted, so a revision is
/// not reported for a damaged request. Only a payload that fails
/// authentication is damaged; one that authenticates but is not a revision
/// this version can read was written by this profile in another format, as
/// by a newer Anvil.
fn revision_undecodable_in(s: &StoreRead<'_>, id: &Id) -> anvil_storage::store::Result<Option<Undecodable>> {
    match s.orphan_revision_attachment_refs_for_retention(id) {
        Ok(_) => Ok(None),
        Err(StoreError::Integrity | StoreError::Serde(_)) => match s.revision_payload_authenticates(id)? {
            Some(false) => Ok(Some(Undecodable::Damaged)),
            _ => Ok(Some(Undecodable::UnknownFormat)),
        },
        Err(e) => Err(e),
    }
}

/// Decide a pass from one consistent read: what to remove and release.
fn plan_in(s: &StoreRead<'_>, cutoff: i64) -> anvil_storage::store::Result<Plan> {
    let rows = rows_digest_in(s)?;
    let entries = attachment_entries_in(s)?;
    // Attached recently, so a draft not saved yet may hold it: the pass
    // after its grace period decides it.
    let recent: HashSet<String> = entries.iter().filter(|e| attached_recently(e, cutoff)).map(|e| e.attachment.clone()).collect();
    // A mark with no time counts as recent, so it would never age: the pass
    // stamps it, and the grace period runs from then.
    let (unstamped, entries): (Vec<AttachmentIndex>, Vec<AttachmentIndex>) =
        entries.into_iter().partition(|e| e.user && e.attached_at.is_none());
    let mut candidates = HashSet::new();
    // By id, and their row ids for the reference scan to skip.
    let (mut orphans, mut orphan_rows) = (Vec::new(), HashSet::new());
    let mut undecodable = Vec::new();
    // Every revision was authenticated by a pass since which no revision or
    // request row was added, removed or written: none is orphaned now.
    let settled = match kept_in(s)?.and_then(|k| k.settled) {
        Some(digest) => digest == revision_rows_digest_in(s)?,
        None => false,
    };
    let revisions = if settled { Vec::new() } else { s.object_meta(kind::REVISION)? };
    for m in revisions {
        // Only the sealed request ID decides orphanhood. Plaintext indexes
        // cannot supply historical ownership, even if they name a live row.
        let refs = match m.id.parse::<Id>() {
            Ok(id) => s.orphan_revision_attachment_refs_for_retention(&id),
            Err(_) => Err(StoreError::Integrity),
        };
        match refs {
            Ok(Some(refs)) => {
                candidates.extend(refs.into_iter().filter(|sha| !recent.contains(sha)));
                orphans.push(m.id.parse::<Id>().map_err(|_| StoreError::Integrity)?);
                orphan_rows.insert(m.id);
            }
            Ok(None) => {}
            Err(StoreError::Integrity | StoreError::Serde(_)) => {
                tracing::warn!(
                    kind = kind::REVISION,
                    id = %m.id,
                    "a stored revision does not decode; its row and stored files are kept"
                );
                undecodable.push(UndecodableObject { kind: kind::REVISION.into(), id: m.id });
            }
            Err(e) => return Err(e),
        }
    }
    let aged: Vec<AttachmentIndex> = entries.into_iter().filter(|e| e.user && !attached_recently(e, cutoff)).collect();
    candidates.extend(aged.iter().map(|e| e.attachment.clone()));
    let (unreferenced, blocked) = reference_scan_in(s, candidates, &orphan_rows)?;
    for object in blocked {
        if !undecodable.contains(&object) {
            undecodable.push(object);
        }
    }
    let held = aged.into_iter().filter(|e| !unreferenced.contains(&e.attachment)).collect();
    Ok(Plan { orphans, unreferenced, held, unstamped, undecodable, rows })
}

/// Carry out `plan` in the write transaction that checked nothing changed
/// since it was read, and keep the pass.
fn apply_in(s: &StoreTx<'_>, plan: Plan) -> anvil_storage::store::Result<StorageCleanup> {
    let mut done = StorageCleanup::default();
    // Stamping releases nothing, so it happens even when nothing else does.
    let now = Utc::now().timestamp_millis();
    let stamped = !plan.unstamped.is_empty();
    for e in plan.unstamped {
        let aging = AttachmentIndex { attached_at: Some(now), ..e };
        s.put(kind::IMPORT_SOURCE, &attachment_index_id(&aging.attachment), None, None, 0.0, &aging)?;
    }
    // An object that does not decode could name any file: nothing is
    // removed, so the files the orphaned revisions name are not lost track
    // of. The next pass tries again.
    if !plan.undecodable.is_empty() {
        done.undecodable = plan.undecodable;
        // What was stamped changed the rows the digest covers.
        let rows = if stamped { rows_digest_in(&s.as_read())? } else { plan.rows };
        keep_in(s, &done, Some(rows), None)?;
        return Ok(done);
    }
    for id in &plan.orphans {
        s.delete(kind::REVISION, id)?;
    }
    done.orphaned_revisions = plan.orphans.len();
    for sha in &plan.unreferenced {
        if drop_attachment_in(s, sha)? {
            done.released_attachments += 1;
        }
    }
    // An aged file a saved item references is held like any other from now
    // on: its mark is dropped, so later passes skip it.
    for e in plan.held {
        let held = AttachmentIndex { user: false, attached_at: None, ..e };
        s.put(kind::IMPORT_SOURCE, &attachment_index_id(&held.attachment), None, None, 0.0, &held)?;
    }
    // The orphans are gone: until a revision or request row changes, none is.
    let settled = revision_rows_digest_in(&s.as_read())?;
    keep_in(s, &done, None, Some(settled))?;
    Ok(done)
}

/// Keep `done` as the last pass, run now.
fn keep_in(s: &StoreTx<'_>, done: &StorageCleanup, rows: Option<String>, settled: Option<String>) -> anvil_storage::store::Result<()> {
    let kept = KeptPass { record: StorageCleanupRecord { ran_at: Utc::now(), result: done.clone() }, rows, settled };
    s.put_note(LAST_PASS_NOTE, &serde_json::to_string(&kept)?)
}

/// The last pass kept. One that does not read counts as none.
fn kept_in(s: &StoreRead<'_>) -> anvil_storage::store::Result<Option<KeptPass>> {
    Ok(s.note(LAST_PASS_NOTE)?.and_then(|n| serde_json::from_str(&n).ok()))
}

/// A digest of what a pass reads: every row of a kind that can reference a
/// stored file, and every attachment index entry, by kind, id, parent and
/// when it was last written. Reads no content.
fn rows_digest_in(s: &StoreRead<'_>) -> anvil_storage::store::Result<String> {
    let mut digest = Sha256::new();
    for k in REFERRERS.into_iter().chain([kind::IMPORT_SOURCE]) {
        let mut rows = s.object_meta(k)?;
        rows.sort_by(|a, b| a.id.cmp(&b.id));
        for m in rows {
            digest.update(format!("{k}\0{}\0{}\0{}\n", m.id, m.parent_id.unwrap_or_default(), m.updated_at));
        }
    }
    Ok(hex::encode(digest.finalize()))
}

/// A digest of what decides which revisions are orphaned: every revision
/// row by id, owner, parent and when it was last written, and the id of
/// every request row. Reads no content. A revision's sealed request never
/// changes, so while this digest stays the same, no revision gains or loses
/// its request.
fn revision_rows_digest_in(s: &StoreRead<'_>) -> anvil_storage::store::Result<String> {
    let mut digest = Sha256::new();
    let mut revisions = s.object_meta(kind::REVISION)?;
    revisions.sort_by(|a, b| a.id.cmp(&b.id));
    for m in revisions {
        let (owner, parent) = (m.workspace_id.unwrap_or_default(), m.parent_id.unwrap_or_default());
        digest.update(format!("{}\0{}\0{owner}\0{parent}\0{}\n", kind::REVISION, m.id, m.updated_at));
    }
    let mut requests: Vec<String> = s.object_meta(kind::REQUEST)?.into_iter().map(|m| m.id).collect();
    requests.sort();
    for id in requests {
        digest.update(format!("{}\0{id}\n", kind::REQUEST));
    }
    Ok(hex::encode(digest.finalize()))
}
