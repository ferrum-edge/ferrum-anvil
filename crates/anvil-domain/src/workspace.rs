use crate::Id;
use crate::auth::AuthConfig;
use crate::request::{AttachmentRef, RequestSpec};
use crate::secret::SensitiveValue;
use crate::settings::SettingsOverrides;
use chrono::{DateTime, Utc};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

/// Common persistent metadata.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct Meta {
    pub id: Id,
    pub schema_version: u32,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

impl Meta {
    pub fn new() -> Self {
        let now = Utc::now();
        Meta { id: Id::new(), schema_version: crate::SCHEMA_VERSION, created_at: now, updated_at: now }
    }
}

impl Default for Meta {
    fn default() -> Self {
        Meta::new()
    }
}

/// Variable in a workspace base set, an environment, a folder or a request.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct Variable {
    pub name: String,
    pub value: SensitiveValue,
    /// Secret variables are masked, redacted from history/reports and replaced
    /// by placeholders in safe-share exports.
    #[serde(default)]
    pub secret: bool,
    #[serde(default = "crate::request::default_true")]
    pub enabled: bool,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub description: String,
}

impl Variable {
    pub fn plain(name: &str, value: &str) -> Self {
        Variable { name: name.into(), value: SensitiveValue::template(value), secret: false, enabled: true, description: String::new() }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct Workspace {
    #[serde(flatten)]
    pub meta: Meta,
    pub name: String,
    #[serde(default)]
    pub description: String,
    #[serde(default)]
    pub settings: SettingsOverrides,
    #[serde(default)]
    pub variables: Vec<Variable>,
    #[serde(default)]
    pub auth: AuthConfig,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub active_environment_id: Option<Id>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct Folder {
    #[serde(flatten)]
    pub meta: Meta,
    pub workspace_id: Id,
    /// `None` = top level of the workspace.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub parent_id: Option<Id>,
    pub name: String,
    #[serde(default)]
    pub description: String,
    /// Fractional ordering key among siblings.
    pub sort_key: f64,
    #[serde(default)]
    pub settings: SettingsOverrides,
    #[serde(default)]
    pub variables: Vec<Variable>,
    #[serde(default)]
    pub auth: AuthConfig,
    #[serde(default)]
    pub tags: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct RequestDefinition {
    #[serde(flatten)]
    pub meta: Meta,
    pub workspace_id: Id,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub folder_id: Option<Id>,
    pub name: String,
    #[serde(default)]
    pub description: String,
    #[serde(default)]
    pub tags: Vec<String>,
    #[serde(default)]
    pub favorite: bool,
    pub sort_key: f64,
    pub spec: RequestSpec,
    /// Latest immutable revision id (updated on explicit save).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub revision_id: Option<Id>,
}

/// Immutable snapshot of a request spec. History and run reports reference
/// revisions, so editing a request never rewrites past outcomes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct RequestRevision {
    pub id: Id,
    pub request_id: Id,
    pub created_at: DateTime<Utc>,
    /// SHA-256 of the canonical JSON of `spec`.
    pub spec_sha256: String,
    pub spec: RequestSpec,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct Environment {
    #[serde(flatten)]
    pub meta: Meta,
    pub workspace_id: Id,
    pub name: String,
    #[serde(default)]
    pub variables: Vec<Variable>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum DatasetFormat {
    Csv,
    Json,
}

/// Iteration data (CSV rows / JSON array of objects).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct Dataset {
    #[serde(flatten)]
    pub meta: Meta,
    pub workspace_id: Id,
    pub name: String,
    pub format: DatasetFormat,
    pub attachment: AttachmentRef,
    /// Columns that hold secrets (masked and redacted in reports).
    #[serde(default)]
    pub sensitive_columns: Vec<String>,
}

/// Ordered chain of saved requests executed by the collection runner.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct Scenario {
    #[serde(flatten)]
    pub meta: Meta,
    pub workspace_id: Id,
    pub name: String,
    #[serde(default)]
    pub description: String,
    pub steps: Vec<ScenarioStep>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dataset_id: Option<Id>,
    #[serde(default)]
    pub iterations: u32,
    /// Stop the iteration at the first failed step.
    #[serde(default)]
    pub stop_on_failure: bool,
    /// Imported scenarios are not runnable until the user explicitly trusts them.
    #[serde(default)]
    pub trusted: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct ScenarioStep {
    pub request_id: Id,
    #[serde(default = "crate::request::default_true")]
    pub enabled: bool,
    /// Delay before this step (think time).
    #[serde(default)]
    pub delay_ms: u64,
}

/// Local profile (a selector, not an OS security boundary).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct UserProfile {
    #[serde(flatten)]
    pub meta: Meta,
    pub display_name: String,
    pub protection: ProtectionMode,
    /// Provider identity bound to this profile (identity only — never a key).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub linked_identity: Option<LinkedIdentity>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ProtectionMode {
    /// Data encrypted with a key held by the OS credential store; no separate
    /// unlock beyond the OS session.
    OsKeychain,
    /// Data encrypted with a key wrapped by a passphrase (Argon2id) and a
    /// recovery key. Unlock required at start and after lock.
    Passphrase,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct LinkedIdentity {
    /// `google`, `github`, `facebook`, or `mock` (CI only).
    pub provider: String,
    /// Provider subject identifier.
    pub subject: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub email: Option<String>,
    pub linked_at: DateTime<Utc>,
    /// Require a fresh provider authentication before local unlock
    /// (online-only policy; offline unlock then needs the recovery path).
    #[serde(default)]
    pub require_fresh_login: bool,
}
