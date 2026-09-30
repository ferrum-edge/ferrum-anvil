//! API standards: the rulesets a profile lints OpenAPI descriptions with
//! (`anvil_contract`), kept in the app settings, and linting of imported
//! or chosen descriptions.
//!
//! Rulesets are layered in order: Anvil's recommended rules when included,
//! then every enabled ruleset. A ruleset is checked in that context when it
//! is added, enabled or replaced, so a stored set always loads.

use crate::{App, AppError, Result};
use anvil_contract::{LintOptions, LintReport, RuleInfo, RuleSet, RulesetSummary, Spec};
use anvil_domain::Id;
use anvil_domain::settings::{ApiStandards, AppSettings, StoredRuleset};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// Largest ruleset kept (the settings are read on every send).
pub const MAX_STORED_RULESET_BYTES: usize = 256 * 1024;
/// Most rulesets kept.
pub const MAX_STORED_RULESETS: usize = 16;

/// The rules in effect, for listing.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StandardsView {
    pub standards: ApiStandards,
    pub sources: Vec<RulesetSummary>,
    pub rules: Vec<RuleInfo>,
    /// Rules a later ruleset turned off.
    pub disabled: Vec<String>,
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
        Ok(self.settings()?.api_standards)
    }

    /// The layered rules, with where each came from.
    pub fn standards_view(&self) -> Result<StandardsView> {
        let standards = self.api_standards()?;
        let set = layered(&standards)?;
        Ok(StandardsView { sources: set.sources.clone(), rules: set.list(), disabled: set.disabled.clone(), standards })
    }

    fn update_standards(&self, f: impl FnOnce(&mut ApiStandards) -> Result<()>) -> Result<ApiStandards> {
        let mut settings = self.settings()?;
        let mut next = settings.api_standards.clone();
        f(&mut next)?;
        // The result must load, as it will be used.
        layered(&next)?;
        settings.api_standards = next.clone();
        self.save_settings(&settings)?;
        Ok(next)
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
        let mut next = settings.clone();
        next.api_standards = self.api_standards()?;
        self.save_settings(&next)
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
