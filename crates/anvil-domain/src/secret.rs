use crate::Id;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

/// Reference to a value held in the encrypted vault. The value itself never
/// appears in ordinary object graphs, logs or safe-share exports.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
pub struct SecretRef {
    pub id: Id,
    /// Human label shown in the UI and in export previews ("prod API key").
    pub label: String,
}

/// A field that may carry sensitive material (password, token, key).
///
/// * `Template` — text that may contain `{{variable}}` references. A literal
///   (non-variable) template in a sensitive field is itself treated as
///   sensitive: it is masked in the UI, redacted in history, and replaced by a
///   placeholder in safe-share exports.
/// * `Secret` — a vault reference.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum SensitiveValue {
    Template { value: String },
    Secret { secret: SecretRef },
}

impl Default for SensitiveValue {
    fn default() -> Self {
        SensitiveValue::Template { value: String::new() }
    }
}

impl SensitiveValue {
    pub fn template(value: impl Into<String>) -> Self {
        SensitiveValue::Template { value: value.into() }
    }

    /// True when the value is only variable references (no literal secret
    /// material embedded in the object graph).
    pub fn is_pure_reference(&self) -> bool {
        match self {
            SensitiveValue::Secret { .. } => true,
            SensitiveValue::Template { value } => {
                let t = value.trim();
                t.is_empty() || (t.starts_with("{{") && t.ends_with("}}") && t.matches("{{").count() == 1)
            }
        }
    }
}

/// Marker text substituted wherever a secret would otherwise be displayed or
/// written.
pub const REDACTED: &str = "‹redacted›";
