//! API standards: the rulesets a profile lints OpenAPI descriptions with
//! (`anvil_contract`), kept as separate profile records, and linting of imported
//! or chosen descriptions.
//!
//! Rulesets are layered in order: Anvil's recommended rules when included,
//! then every enabled ruleset. A ruleset is checked in that context when it
//! is added, enabled or replaced, so a stored set always loads.

use crate::{App, AppError, Result, settings_id};
use anvil_contract::{LintOptions, LintReport, RuleInfo, RuleSet, RulesetSummary, Spec};
use anvil_domain::Id;
use anvil_domain::settings::{ApiStandards, ApiStandardsSettings, AppSettings, StoredRuleset};
use anvil_storage::kind;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// Per-ruleset limit shared with the CLI parser.
pub const MAX_STORED_RULESET_BYTES: usize = anvil_contract::ruleset::MAX_RULESET_BYTES;
/// Bound the number and aggregate size of profile ruleset records.
pub const MAX_STORED_RULESETS: usize = anvil_portability::validate::MAX_RULESET_RECORDS;
pub const MAX_STORED_RULESETS_BYTES: usize = anvil_portability::validate::MAX_TOTAL_RULESET_BYTES;

/// The rules in effect, for listing.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StandardsView {
    pub standards: ApiStandards,
    pub sources: Vec<RulesetSummary>,
    pub rules: Vec<RuleInfo>,
    /// Rules a later ruleset turned off.
    pub disabled: Vec<String>,
    /// Why the stored rulesets do not load (a backup restored from another
    /// build, say); `sources` and `rules` are then empty, and the rulesets
    /// can still be disabled or removed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

fn layered(std: &ApiStandards) -> std::result::Result<RuleSet, AppError> {
    let mut set = if std.include_recommended { RuleSet::recommended() } else { RuleSet::default() };
    for r in std.rulesets.iter().filter(|r| r.enabled) {
        set.add(&r.file_name, r.text.as_bytes(), false).map_err(|e| AppError::Invalid(e.to_string()))?;
    }
    Ok(set)
}

impl App {
    pub fn api_standards(&self) -> Result<ApiStandards> {
        let (settings, rulesets) = self.store.read_consistently(|r| {
            Ok((
                r.get::<AppSettings>(kind::APP_SETTINGS, &settings_id())?.unwrap_or_default(),
                r.list::<StoredRuleset>(kind::API_RULESET, None)?,
            ))
        })?;
        Ok(ApiStandards { include_recommended: settings.api_standards.include_recommended, rulesets })
    }

    /// The layered rules, with where each came from.
    pub fn standards_view(&self) -> Result<StandardsView> {
        let standards = self.api_standards()?;
        Ok(match layered(&standards) {
            Ok(set) => {
                StandardsView { sources: set.sources.clone(), rules: set.list(), disabled: set.disabled.clone(), standards, error: None }
            }
            Err(e) => StandardsView { sources: vec![], rules: vec![], disabled: vec![], standards, error: Some(e.to_string()) },
        })
    }

    /// Change the standards in one write transaction (read, check, write),
    /// so concurrent changes and settings saves never undo each other.
    fn update_standards(&self, f: impl FnOnce(&mut ApiStandards) -> Result<()>) -> Result<ApiStandards> {
        self.store.atomically(|tx| {
            let mut settings: AppSettings = tx.get(kind::APP_SETTINGS, &settings_id())?.unwrap_or_default();
            let current = tx.list::<StoredRuleset>(kind::API_RULESET, None)?;
            let mut next = ApiStandards { include_recommended: settings.api_standards.include_recommended, rulesets: current.clone() };
            // The result must load, as it will be used.
            if let Err(e) = f(&mut next).and_then(|()| validate_standards(&next).and_then(|()| layered(&next).map(|_| ()))) {
                return Ok(Err(e));
            }
            settings.api_standards = ApiStandardsSettings { include_recommended: next.include_recommended, legacy_rulesets: vec![] };
            tx.put(kind::APP_SETTINGS, &settings_id(), None, None, 0.0, &settings)?;
            let ids: std::collections::HashSet<Id> = next.rulesets.iter().map(|r| r.id).collect();
            for old in &current {
                if !ids.contains(&old.id) {
                    tx.delete(kind::API_RULESET, &old.id)?;
                }
            }
            for (index, ruleset) in next.rulesets.iter().enumerate() {
                tx.put(kind::API_RULESET, &ruleset.id, None, None, index as f64, ruleset)?;
            }
            Ok(Ok(next))
        })?
    }

    /// Add a ruleset file (enabled, after the others).
    pub fn add_api_ruleset(&self, file_name: &str, bytes: &[u8]) -> Result<StoredRuleset> {
        let stored = stored_ruleset(file_name, bytes)?;
        let out = stored.clone();
        self.update_standards(move |s| {
            if s.rulesets.len() >= MAX_STORED_RULESETS {
                return Err(AppError::Invalid(format!("at most {MAX_STORED_RULESETS} rulesets can be kept")));
            }
            s.rulesets.push(stored);
            Ok(())
        })?;
        Ok(out)
    }

    /// Replace a stored ruleset with a newer file, in place.
    pub fn replace_api_ruleset(&self, id: &Id, file_name: &str, bytes: &[u8]) -> Result<StoredRuleset> {
        let mut stored = stored_ruleset(file_name, bytes)?;
        stored.id = *id;
        let out = stored.clone();
        self.update_standards(move |s| {
            let slot = s.rulesets.iter_mut().find(|r| r.id == stored.id).ok_or_else(|| AppError::NotFound("ruleset".into()))?;
            stored.enabled = slot.enabled;
            *slot = stored;
            Ok(())
        })?;
        Ok(out)
    }

    pub fn remove_api_ruleset(&self, id: &Id) -> Result<ApiStandards> {
        self.update_standards(|s| {
            let before = s.rulesets.len();
            s.rulesets.retain(|r| r.id != *id);
            if s.rulesets.len() == before {
                return Err(AppError::NotFound("ruleset".into()));
            }
            Ok(())
        })
    }

    pub fn set_api_ruleset_enabled(&self, id: &Id, enabled: bool) -> Result<ApiStandards> {
        self.update_standards(|s| {
            let r = s.rulesets.iter_mut().find(|r| r.id == *id).ok_or_else(|| AppError::NotFound("ruleset".into()))?;
            r.enabled = enabled;
            Ok(())
        })
    }

    pub fn set_api_standards_recommended(&self, include: bool) -> Result<ApiStandards> {
        self.update_standards(|s| {
            s.include_recommended = include;
            Ok(())
        })
    }

    /// Save settings edited elsewhere (the settings dialog) without their
    /// API standards: those change only through the functions above, so a
    /// dialog opened before a ruleset was added never drops it.
    pub fn save_settings_keeping_standards(&self, settings: &AppSettings) -> Result<()> {
        self.store.atomically(|tx| {
            let stored: AppSettings = tx.get(kind::APP_SETTINGS, &settings_id())?.unwrap_or_default();
            let mut next = settings.clone();
            next.api_standards = ApiStandardsSettings {
                include_recommended: stored.api_standards.include_recommended,
                legacy_rulesets: vec![],
            };
            tx.put(kind::APP_SETTINGS, &settings_id(), None, None, 0.0, &next)
        })?;
        Ok(())
    }

    /// Lint a description with the profile's standards.
    pub fn lint_spec(&self, bytes: &[u8]) -> Result<LintReport> {
        let rules = layered(&self.api_standards()?)?;
        let spec = Spec::parse(bytes).map_err(|e| AppError::Invalid(e.to_string()))?;
        Ok(anvil_contract::lint(&spec, &rules, &LintOptions::default()))
    }

    /// Lint the stored original of an import (its latest version).
    pub fn lint_imported_spec(&self, import_id: &Id) -> Result<LintReport> {
        let bytes = self.spec_original(import_id)?;
        self.lint_spec(&bytes)
    }

    /// The stored original bytes of an import, by its current or an
    /// earlier import id.
    pub fn spec_original(&self, import_id: &Id) -> Result<Vec<u8>> {
        let rec = self.spec_source_any(import_id)?;
        self.get_attachment(&rec.original_sha256)?.ok_or_else(|| AppError::NotFound("the imported original".into()))
    }
}

fn stored_ruleset(file_name: &str, bytes: &[u8]) -> Result<StoredRuleset> {
    if bytes.len() > MAX_STORED_RULESET_BYTES {
        return Err(AppError::Invalid(format!("the ruleset is {} bytes; at most {MAX_STORED_RULESET_BYTES} are kept", bytes.len())));
    }
    let text = std::str::from_utf8(bytes).map_err(|_| AppError::Invalid("the ruleset is not UTF-8 text".into()))?;
    // Its rules are checked in context when it is stored.
    let summary = anvil_contract::ruleset::describe(file_name, bytes).map_err(|e| AppError::Invalid(e.to_string()))?;
    let (name, version) = (summary.name, summary.version);
    Ok(StoredRuleset {
        id: Id::new(),
        name,
        file_name: file_name.to_string(),
        version,
        text: text.to_string(),
        sha256: hex::encode(Sha256::digest(bytes)),
        added_at: chrono::Utc::now(),
        enabled: true,
    })
}

fn validate_standards(standards: &ApiStandards) -> Result<()> {
    if standards.rulesets.len() > MAX_STORED_RULESETS {
        return Err(AppError::Invalid(format!("at most {MAX_STORED_RULESETS} rulesets can be kept")));
    }
    let total: usize = standards.rulesets.iter().map(|r| r.text.len()).sum();
    if total > MAX_STORED_RULESETS_BYTES {
        return Err(AppError::Invalid(format!("rulesets together are {total} bytes; at most {MAX_STORED_RULESETS_BYTES} are kept")));
    }
    Ok(())
}
