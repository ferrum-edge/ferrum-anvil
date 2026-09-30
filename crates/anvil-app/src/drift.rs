//! Contract drift of an imported OpenAPI description: the exchanges in
//! history that belong to the import's collection, compared with the
//! import's stored original (`anvil_contract::drift`), and revising the
//! import with chosen suggestions.
//!
//! An exchange belongs to the import when its saved request was imported
//! from it (its `ImportSource`, under the current or an earlier import id),
//! or sits under the import root, or, for an import that made its own
//! workspace, is any request of that workspace: a request the user added
//! next to the imported ones is checked against the same description, so
//! paths the description lacks show up. Unsaved drafts are not recorded
//! with a request id and are not included.

use crate::specs::SpecSourceRecord;
use crate::{App, AppError, Result};
use anvil_contract::observe::{BodyBudget, MAX_BODY_CHECKED, ObservedBody, ObservedResponse, body_of, query_names};
use anvil_contract::{DriftOptions, DriftReport, Observation, Revision, Spec};
use anvil_domain::Id;
use anvil_domain::execution::{BodyCompleteness, ContentDecoding, ExecutionRecord, exchange_duration_us};
use anvil_domain::workspace::RequestDefinition;
use anvil_import::{ReimportApproval, ReimportPlan};
use std::collections::{HashMap, HashSet};

/// History records read for a report at most.
pub const MAX_DRIFT_RECORDS: usize = 1_000;
/// History entries of the workspace scanned for them (most belong to other
/// requests in a busy workspace).
const MAX_DRIFT_SCAN: usize = 20 * MAX_DRIFT_RECORDS;

/// The exchanges of an import's collection, as observations.
pub struct Collected {
    pub observations: Vec<Observation>,
    /// Records of the workspace that were read.
    pub scanned: usize,
}

impl App {
    /// The saved requests an import's drift covers, with the operation each
    /// was imported from.
    fn drift_requests(&self, rec: &SpecSourceRecord) -> Result<HashMap<Id, Option<String>>> {
        let requests: Vec<RequestDefinition> = self.requests(&rec.workspace_id)?;
        let ids: HashSet<Id> = std::iter::once(rec.source.import_id).chain(rec.previous_import_ids.iter().copied()).collect();
        let under_root: HashSet<Id> = match rec.root_folder_id {
            Some(root) => {
                let folders = self.folders(&rec.workspace_id)?;
                let mut inside: HashSet<Id> = HashSet::from([root]);
                // Parents precede children only by chance; iterate to a fixed point.
                loop {
                    let before = inside.len();
                    for f in &folders {
                        if f.parent_id.is_some_and(|p| inside.contains(&p)) {
                            inside.insert(f.meta.id);
                        }
                    }
                    if inside.len() == before {
                        break;
                    }
                }
                inside
            }
            None => HashSet::new(),
        };
        Ok(requests
            .into_iter()
            .filter_map(|r| {
                let src = r.spec.source.as_ref().filter(|s| ids.contains(&s.import_id));
                let belongs = src.is_some() || rec.root_folder_id.is_none() || r.folder_id.is_some_and(|f| under_root.contains(&f));
                belongs.then(|| (r.meta.id, src.map(|s| s.operation_key.clone())))
            })
            .collect())
    }

    /// The newest `limit` exchanges of the import's collection.
    pub fn drift_observations(&self, import_id: &Id, limit: usize) -> Result<Collected> {
        let rec = self.spec_source_any(import_id)?;
        let requests = self.drift_requests(&rec)?;
        let entries = self.store.list_history(Some(&rec.workspace_id), None, (limit.min(MAX_DRIFT_RECORDS) * 20).min(MAX_DRIFT_SCAN))?;
        let mut observations = vec![];
        let mut scanned = 0;
        let mut budget = BodyBudget::default();
        for e in entries {
            let Some(rid) = e.request_id.as_deref().and_then(|r| r.parse::<Id>().ok()) else { continue };
            let Some(hint) = requests.get(&rid) else { continue };
            scanned += 1;
            let Some((record, body)) = self.store.get_history::<ExecutionRecord>(&e.id)? else { continue };
            let body = body.map(|b| b.to_vec());
            observations.push(observation(&record, body.as_deref(), hint.clone(), &mut budget));
            if observations.len() >= limit.min(MAX_DRIFT_RECORDS) {
                break;
            }
        }
        Ok(Collected { observations, scanned })
    }

    fn drift_spec(&self, import_id: &Id) -> Result<Spec> {
        let bytes = self.spec_original(import_id)?;
        Spec::parse(&bytes).map_err(|e| AppError::Invalid(format!("the imported original is not an OpenAPI description: {e}")))
    }

    /// Compare the import's collection history with its description.
    pub fn drift_report(&self, import_id: &Id, limit: usize) -> Result<DriftReport> {
        let spec = self.drift_spec(import_id)?;
        let c = self.drift_observations(import_id, limit)?;
        let mut report = anvil_contract::analyze(&spec, &c.observations, &DriftOptions::default());
        if c.observations.is_empty() {
            report.notes.push("No sends of this collection are in history yet: send its requests (or run them) and check again.".into());
        }
        Ok(report)
    }

    /// Check one recorded exchange against the description its request was
    /// imported from (or whose collection it is in). `None` when it belongs
    /// to no OpenAPI import.
    pub fn drift_check_execution(&self, execution_id: &Id) -> Result<Option<(SpecSourceRecord, DriftReport)>> {
        let Some((record, body)) = self.store.get_history::<ExecutionRecord>(&execution_id.to_string())? else {
            return Err(AppError::NotFound("the exchange (history is off, or it was pruned)".into()));
        };
        let (Some(ws), Some(rid)) = (record.workspace_id, record.request_id) else { return Ok(None) };
        let sources: Vec<SpecSourceRecord> =
            self.spec_sources(&ws)?.into_iter().filter(|s| s.source.kind == anvil_import::SourceKind::OpenApi).collect();
        for rec in sources {
            let requests = self.drift_requests(&rec)?;
            let Some(hint) = requests.get(&rid) else { continue };
            let spec = self.drift_spec(&rec.source.import_id)?;
            let body = body.map(|b| b.to_vec());
            let obs = observation(&record, body.as_deref(), hint.clone(), &mut BodyBudget::default());
            return Ok(Some((rec, anvil_contract::analyze(&spec, &[obs], &DriftOptions::default()))));
        }
        Ok(None)
    }

    /// The import's description revised with the suggestions `ids` of a
    /// fresh report.
    pub fn drift_revise(&self, import_id: &Id, ids: &[String], limit: usize) -> Result<Revision> {
        let spec = self.drift_spec(import_id)?;
        let c = self.drift_observations(import_id, limit)?;
        let report = anvil_contract::analyze(&spec, &c.observations, &DriftOptions::default());
        Ok(anvil_contract::revise(&spec, &report, ids))
    }

    /// [`App::drift_revise`] for saving a revision the user chose from a
    /// report they are looking at: a suggestion id names the change on this
    /// description, so an id the fresh report lacks means that change is
    /// different now (new traffic, a new version) and nothing is written.
    pub fn drift_revise_exact(&self, import_id: &Id, ids: &[String], limit: usize) -> Result<Revision> {
        let spec = self.drift_spec(import_id)?;
        let c = self.drift_observations(import_id, limit)?;
        let report = anvil_contract::analyze(&spec, &c.observations, &DriftOptions::default());
        let changed = ids.iter().filter(|id| !report.suggestions.iter().any(|s| &s.id == *id)).count();
        if changed > 0 {
            return Err(AppError::Invalid(format!("{changed} of the chosen revisions changed since this report; check again")));
        }
        Ok(anvil_contract::revise(&spec, &report, ids))
    }

    /// What reimporting the revised description would change.
    pub fn drift_reimport_plan(&self, import_id: &Id, ids: &[String], limit: usize) -> Result<(Revision, ReimportPlan)> {
        let rev = self.drift_revise(import_id, ids, limit)?;
        let current = self.spec_source_any(import_id)?.source.import_id;
        let plan = self.spec_reimport_plan(&current, rev.text.as_bytes())?;
        Ok((rev, plan))
    }

    /// Reimport the revised description as the import's new version: new
    /// operations become requests, safe updates apply, and conflicts and
    /// removals are kept as they are (see `docs/import.md#reimport`).
    ///
    /// The analysis runs again here, so `digest` (the previewed
    /// [`Revision::digest`]) must match: new traffic or a new version in
    /// between refuses the update instead of applying something else.
    pub fn drift_reimport_apply(&self, import_id: &Id, ids: &[String], limit: usize, digest: &str) -> Result<(Revision, usize)> {
        let rev = self.drift_revise(import_id, ids, limit)?;
        if rev.digest != digest {
            return Err(AppError::Invalid(
                "the revision changed since the preview (new traffic or a new version); preview it again".into(),
            ));
        }
        if rev.applied.is_empty() {
            return Err(AppError::Invalid("none of the chosen suggestions applies any more; check again".into()));
        }
        let rec = self.spec_source_any(import_id)?;
        let n = self.spec_reimport_apply(&rec.source.import_id, rev.text.as_bytes(), &rec.file_name, &ReimportApproval::default())?;
        Ok((rev, n))
    }
}

/// An observation of a recorded exchange. `raw` is the stored response
/// body (still content-encoded), when history kept it; bodies parsed count
/// against `budget`.
pub fn observation(r: &ExecutionRecord, raw: Option<&[u8]>, hint: Option<String>, budget: &mut BodyBudget) -> Observation {
    let response = r.response.as_ref().map(|resp| {
        let ct = resp.body.content_type.clone();
        let complete = matches!(resp.body.completeness, BodyCompleteness::Complete) && !resp.body.display_truncated;
        let body = match (resp.body.completeness, raw) {
            (BodyCompleteness::NoBody, _) => ObservedBody::Empty,
            (_, None) if resp.body.wire_bytes == 0 => ObservedBody::Empty,
            (_, None) => ObservedBody::Unavailable("history keeps no response bodies (Settings → History)".into()),
            (_, Some(bytes)) => {
                // Decoding stops just past what is checked (a larger body
                // is reported as too large).
                let limit = r.prepared.settings.limits.max_decoded_bytes.min(MAX_BODY_CHECKED as u64 + 1);
                match anvil_transport::decode::decode(resp.body.content_encoding.as_deref(), bytes, limit) {
                    anvil_transport::decode::DecodeOutcome::Identity => body_of(ct.as_deref(), bytes, complete, budget),
                    anvil_transport::decode::DecodeOutcome::Decoded { bytes, truncated_at_limit } => {
                        body_of(ct.as_deref(), &bytes, complete && !truncated_at_limit, budget)
                    }
                    _ => ObservedBody::Unavailable("the body could not be decoded".into()),
                }
            }
        };
        let decoding_ok = !matches!(resp.body.decoding, Some(ContentDecoding::Failed | ContentDecoding::Unsupported));
        ObservedResponse {
            status: resp.status,
            content_type: ct,
            headers: resp.headers.iter().map(|h| h.name.to_ascii_lowercase()).collect(),
            bytes: resp.body.decoded_bytes.filter(|_| decoding_ok).or(Some(resp.body.wire_bytes)),
            body,
        }
    });
    Observation {
        id: r.id.to_string(),
        at: Some(r.started_at),
        method: r.prepared.method.to_ascii_uppercase(),
        url: r.prepared.url.clone(),
        operation_hint: hint,
        request_content_type: r.prepared.content_type.clone(),
        request_bytes: r.prepared.body_bytes,
        query: query_names(&r.prepared.url),
        request_headers: r.prepared.headers.iter().map(|h| h.name.to_ascii_lowercase()).collect(),
        response,
        latency_ms: exchange_duration_us(&r.attempts).map(|us| us as f64 / 1000.0),
    }
}
