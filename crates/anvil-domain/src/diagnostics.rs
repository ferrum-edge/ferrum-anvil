use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

/// Qualitative confidence. Anvil never invents probability percentages.
/// `Unknown` is a correct answer when evidence is insufficient.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum Confidence {
    ConflictingEvidence,
    Unknown,
    Likely,
    Confirmed,
}

/// Which leg / owner of the path a claim is about.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum SourceScope {
    /// Anvil itself, before any network activity.
    LocalClient,
    ForwardProxy,
    /// Anvil ↔ the peer it connected to (gateway or ordinary destination).
    ClientToPeer,
    /// The gateway's own admission/configuration/policy decisions.
    GatewayAdmission,
    /// The gateway ↔ its upstream backend.
    GatewayToUpstream,
    UpstreamApplication,
    /// Delivery of an already-started response.
    ResponseDelivery,
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum Owner {
    /// The person using Anvil (request, credentials, local settings).
    Caller,
    GatewayOperator,
    ApiOwner,
    NetworkAdministrator,
    IdentityProvider,
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum Severity {
    Info,
    Warning,
    Error,
}

/// Where a piece of evidence came from. Rules weight native measurements and
/// trusted gateway fields above generic status meanings and body heuristics.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceSource {
    LocalValidation,
    NativeTransport,
    TlsVerifier,
    HttpStatus,
    HttpHeader,
    HttpTrailer,
    GrpcStatus,
    WebSocketClose,
    BodyCompletion,
    /// Parsed body structure (SOAP fault, GraphQL errors). Weak evidence of origin.
    BodyContent,
    /// Ferrum marker from a destination the user explicitly trusts as Ferrum.
    FerrumMarkerTrusted,
    /// Ferrum-like marker from an unverified destination.
    FerrumMarkerUnverified,
    /// Authenticated gateway diagnostic detail (versioned contract).
    GatewayDetail,
    Configuration,
    Assertion,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct Evidence {
    pub source: EvidenceSource,
    /// Machine key, e.g. `failure.kind`, `header.x-gateway-error`, `tls.alert`.
    pub key: String,
    /// Redacted value as observed.
    pub value: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub attempt: Option<u32>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct Remediation {
    pub text: String,
    pub owner: Owner,
}

/// A single diagnostic claim with its evidence and confidence.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct DiagnosticFinding {
    /// Stable finding code, e.g. `client.tls.untrusted_issuer`.
    pub code: String,
    pub rule_id: String,
    pub rule_version: u32,
    pub title: String,
    pub explanation: String,
    pub scope: SourceScope,
    pub confidence: Confidence,
    pub severity: Severity,
    pub evidence: Vec<Evidence>,
    /// Other explanations consistent with the same evidence.
    pub alternatives: Vec<String>,
    /// Statements this evidence does NOT establish (shown explicitly).
    pub does_not_prove: Vec<String>,
    pub remediation: Vec<Remediation>,
    pub owner: Owner,
    /// What additional evidence would confirm or refute the claim.
    pub confirm_with: Vec<String>,
}
