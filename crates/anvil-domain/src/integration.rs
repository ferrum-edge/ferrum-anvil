use crate::Id;
use crate::secret::SensitiveValue;
use crate::tls::HostBinding;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

/// Explicit user decision that a destination is a Ferrum Edge gateway.
///
/// Without such a profile a `X-Gateway-Error` header is only a "Ferrum-like
/// marker" from an unverified peer: any server can emit that header.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct IntegrationProfile {
    pub id: Id,
    pub workspace_id: Id,
    pub name: String,
    #[serde(flatten)]
    pub kind: IntegrationKind,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub updated_at: chrono::DateTime<chrono::Utc>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum IntegrationKind {
    FerrumGateway {
        /// Hosts (and optional ports) that are this gateway's frontends.
        hosts: Vec<HostBinding>,
        /// Compatibility catalog id, e.g. `ferrum-edge-0.9.5`.
        compatibility_id: String,
        /// Only treat markers as gateway-authored when the TLS peer was
        /// verified. Plain-HTTP trust is allowed only for explicitly marked
        /// local/lab destinations and caps confidence at `likely`.
        #[serde(default = "default_true")]
        require_verified_tls: bool,
        /// Optional authorized diagnostic detail endpoint (proposed gateway
        /// contract; unavailable on current releases).
        #[serde(default, skip_serializing_if = "Option::is_none")]
        detail: Option<DiagnosticDetailAccess>,
        /// Link to Foundry/Nexus for read-only context (never auto-edited).
        #[serde(default, skip_serializing_if = "Option::is_none")]
        console_url: Option<String>,
    },
}

fn default_true() -> bool {
    true
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct DiagnosticDetailAccess {
    pub base_url: String,
    /// Dedicated least-privilege diagnostic credential (never an admin JWT).
    pub credential: SensitiveValue,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub namespace: Option<String>,
}
