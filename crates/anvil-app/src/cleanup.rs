//! Storage cleanup when a profile opens: revisions and stored files that no
//! saved item can reach any more are removed. A file any saved item of any
//! workspace references is never released.

use crate::workspace::{AttachmentIndex, attachment_entries_in, attachment_index_id, drop_attachment_in, reference_scan_in};
use crate::{App, Result};
use anvil_domain::Id;
use anvil_domain::workspace::RequestRevision;
use anvil_storage::{StoreError, kind};
use serde::Serialize;
use std::collections::HashSet;
use std::time::Duration;

/// How long a file a user attached ([`App::put_attachment`]) waits for a
/// saved item to reference it. Once it is older and no saved item does, the
/// cleanup at profile open releases it. Attaching the same content again
/// restarts the wait, and a save that names a released file is refused
/// ("attach it again"), so no saved item names content that is gone.
pub const ATTACHMENT_GRACE: Duration = Duration::from_secs(30 * 24 * 60 * 60);

/// What one cleanup pass did.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
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
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct UndecodableObject {
    pub kind: String,
    pub id: String,
}

impl App {
    /// Remove the revisions of requests that no longer exist (builds before
    /// deletes removed them left them behind) and release the stored files
    /// that only they named, and the files a user attached longer than
    /// [`ATTACHMENT_GRACE`] ago that no saved item references. What
    /// references a file is checked in the write transaction that releases
    /// it. Runs when a profile opens; a pass with nothing to release decodes
    /// only the attachment index.
    pub fn clean_up_storage(&self) -> Result<StorageCleanup> {
        let cutoff = chrono::Utc::now().timestamp_millis().saturating_sub(ATTACHMENT_GRACE.as_millis() as i64);
        Ok(self.store.atomically(|s| {
            let mut done = StorageCleanup::default();
            let mut candidates = HashSet::new();
            let requests: HashSet<String> = s.object_meta(kind::REQUEST)?.into_iter().map(|m| m.id).collect();
            // By id, and their row ids for the reference scan to skip.
            let (mut orphans, mut orphan_rows) = (Vec::new(), HashSet::new());
            for m in s.object_meta(kind::REVISION)? {
                // Every writer files a revision under its request; one filed
                // under none is kept.
                if m.parent_id.as_ref().is_none_or(|p| requests.contains(p)) {
                    continue;
                }
                let Ok(id) = m.id.parse::<Id>() else { continue };
                // One that does not decode goes too; the files it named are kept.
                match s.get::<RequestRevision>(kind::REVISION, &id) {
                    Ok(Some(rev)) => {
                        let spec = serde_json::to_value(&rev.spec)?;
                        crate::exec::collect_attachments(&spec, &mut |sha| {
                            candidates.insert(sha.to_string());
                        });
                    }
                    Ok(None) | Err(StoreError::Integrity | StoreError::Serde(_)) => {}
                    Err(e) => return Err(e),
                }
                orphans.push(id);
                orphan_rows.insert(m.id);
            }
            let mut aged = attachment_entries_in(s)?;
            aged.retain(|e| e.user && e.attached_at.is_some_and(|t| t < cutoff));
            candidates.extend(aged.iter().map(|e| e.attachment.clone()));
            let (unreferenced, undecodable) = reference_scan_in(s, candidates, &orphan_rows)?;
            // An object that does not decode could name any file: nothing is
            // removed, so the files the orphaned revisions name are not lost
            // track of. The next open tries again.
            if !undecodable.is_empty() {
                done.undecodable = undecodable;
                return Ok(done);
            }
            for id in &orphans {
                s.delete(kind::REVISION, id)?;
            }
            done.orphaned_revisions = orphans.len();
            for sha in &unreferenced {
                if drop_attachment_in(s, sha)? {
                    done.released_attachments += 1;
                }
            }
            // An aged file a saved item references is held like any other
            // from now on: its mark is dropped, so later passes skip it.
            for e in aged.into_iter().filter(|e| !unreferenced.contains(&e.attachment)) {
                let held = AttachmentIndex { user: false, attached_at: None, ..e };
                s.put(kind::IMPORT_SOURCE, &attachment_index_id(&held.attachment), None, None, 0.0, &held)?;
            }
            Ok(done)
        })?)
    }

    /// [`App::clean_up_storage`] when a profile opens. A failure does not
    /// stop the profile opening: it is logged, and the next open tries again.
    pub(crate) fn clean_up_storage_on_open(&self) {
        if let Err(e) = self.clean_up_storage() {
            tracing::warn!(error = %e, "storage cleanup did not finish; it runs again when the profile next opens");
        }
    }
}
