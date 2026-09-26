//! SPIFFE Workload API: the settings that make Anvil fetch an X.509-SVID
//! (a TLS client identity) or a JWT-SVID (a bearer credential) from a local
//! Workload API endpoint (a SPIRE agent, Ferrum Edge's in-process Workload
//! API, or any implementation of the standard `SpiffeWorkloadAPI` service),
//! and the evidence recorded when it does.
//!
//! The Workload API is a local, unauthenticated-by-TLS channel: the server
//! identifies the caller by the socket's kernel peer credentials. The
//! evidence therefore records which endpoint was dialed and what it
//! answered, and never the SVID private key or the JWT-SVID itself.

use crate::execution::CertificateSummary;
use crate::secret::SensitiveValue;
use chrono::{DateTime, Utc};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

/// Environment variable that names the Workload API endpoint when a profile
/// leaves its endpoint empty (SPIFFE Workload Endpoint specification §4).
pub const SPIFFE_ENDPOINT_SOCKET: &str = "SPIFFE_ENDPOINT_SOCKET";

/// Where a JWT-SVID comes from.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum JwtSvidSource {
    /// `FetchJWTSVID` from the Workload API for the configured audiences,
    /// cached in memory until shortly before it expires.
    WorkloadApi,
    /// A token held in a variable or the vault (for example `{{jwt_svid}}`).
    Value { token: SensitiveValue },
    /// A token file written by another agent (for example spiffe-helper),
    /// read at send time.
    File { path: String },
}

/// JWT-SVID bearer auth (SPIFFE JWT-SVID specification). Anvil checks the
/// token locally before sending it and never mints one itself.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct JwtSvidConfig {
    pub source: JwtSvidSource,
    /// Audiences requested from the Workload API; every one must be in the
    /// token's `aud` before it is sent. At least one is required.
    pub audiences: Vec<String>,
    /// Workload API endpoint: `unix:///path/to/socket` (or `npipe:name` on
    /// Windows). Empty: the `SPIFFE_ENDPOINT_SOCKET` environment variable.
    /// Used by the `workload_api` source and by bundle verification.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub endpoint: String,
    /// With the `workload_api` source, the SPIFFE ID to request (a workload
    /// may hold several); otherwise the subject the token must carry.
    /// Empty: the workload's default identity / any subject.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub spiffe_id: Option<String>,
    /// Verify the signature against the trust domain's JWT bundle from
    /// `FetchJWTBundles` before sending.
    #[serde(default)]
    pub verify_with_bundles: bool,
    /// Send even when a local check fails, to see how a verifier treats a
    /// bad JWT-SVID. Off by default: a failed check stops the request.
    #[serde(default)]
    pub send_despite_failed_checks: bool,
    /// Header carrying the token (default `Authorization`).
    #[serde(default = "default_auth_header")]
    pub header_name: String,
    #[serde(default = "default_bearer_prefix")]
    pub prefix: String,
}

fn default_auth_header() -> String {
    "Authorization".into()
}

fn default_bearer_prefix() -> String {
    "Bearer".into()
}

/// How the endpoint was chosen.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum WorkloadEndpointSource {
    /// The profile's `endpoint` setting.
    Setting,
    /// The `SPIFFE_ENDPOINT_SOCKET` environment variable.
    Environment,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum WorkloadRpc {
    #[serde(rename = "FetchX509SVID")]
    FetchX509Svid,
    #[serde(rename = "FetchJWTSVID")]
    FetchJwtSvid,
    #[serde(rename = "FetchJWTBundles")]
    FetchJwtBundles,
}

impl WorkloadRpc {
    pub fn method(self) -> &'static str {
        match self {
            WorkloadRpc::FetchX509Svid => "FetchX509SVID",
            WorkloadRpc::FetchJwtSvid => "FetchJWTSVID",
            WorkloadRpc::FetchJwtBundles => "FetchJWTBundles",
        }
    }
}

/// What one Workload API call ended with.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "result", rename_all = "snake_case")]
pub enum WorkloadCallResult {
    Ok,
    /// Anvil could not connect or speak HTTP/2 gRPC to the endpoint.
    Unavailable {
        detail: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        io_error_kind: Option<String>,
    },
    /// No answer within the deadline.
    Timeout {
        deadline_ms: u64,
    },
    /// The endpoint answered with a non-OK gRPC status. `message` is the
    /// endpoint's `grpc-message` (untrusted text, bounded).
    Status {
        code: i32,
        code_name: String,
        message: String,
    },
    /// An OK answer that carried no usable identity (no SVIDs, or none with
    /// the requested SPIFFE ID).
    NoIdentity {
        detail: String,
    },
    /// The answer could not be decoded as the Workload API message.
    Malformed {
        detail: String,
    },
}

/// One Workload API call made for an execution.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct WorkloadApiCall {
    pub rpc: WorkloadRpc,
    /// The endpoint dialed, as a URI (`unix:///run/spire/agent.sock`).
    pub endpoint: String,
    pub endpoint_source: WorkloadEndpointSource,
    /// What the call was for (`TLS profile 'mesh client'`, `JWT-SVID auth`).
    pub purpose: String,
    /// Served from Anvil's in-memory cache (fetched by an earlier execution).
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub cached: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub duration_us: Option<u64>,
    /// The uid this process presents in the socket's peer credentials — what
    /// a Workload API server attests. Recorded when no identity was issued.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub caller_uid: Option<u32>,
    pub result: WorkloadCallResult,
}

/// The X.509-SVID used as a TLS client identity (public data only).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct X509SvidSummary {
    pub tls_profile: String,
    pub spiffe_id: String,
    pub certificate: CertificateSummary,
    /// Certificates in the SVID chain (leaf first).
    pub chain_length: u32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hint: Option<String>,
    /// SPIFFE IDs of every SVID the endpoint returned (the first is the default).
    pub offered_spiffe_ids: Vec<String>,
    /// The SVID's trust-domain bundle was added to the profile's trust anchors.
    pub bundle_trusted: bool,
    /// CA certificates in that bundle.
    pub bundle_certificates: u32,
    /// Federated trust domains the endpoint also sent bundles for (recorded,
    /// never trusted: one TLS profile holds one trust bundle).
    pub federated_trust_domains: Vec<String>,
    /// When Anvil will fetch a fresh SVID (half its lifetime, as SPIFFE
    /// agents rotate).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub refresh_after: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum JwtSvidSourceKind {
    WorkloadApi,
    Value,
    File,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum JwtSvidCheckKind {
    /// Three base64url segments with JSON header and claims.
    Format,
    /// `alg` present and asymmetric (never `none` or HMAC).
    Algorithm,
    /// `sub` is a workload SPIFFE ID (and the configured one, when set).
    Subject,
    /// Every requested audience is in `aud`.
    Audience,
    /// `exp` present and in the future by this machine's clock.
    Expiry,
    /// Signature verified against the trust domain's JWT bundle.
    Signature,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum CheckResult {
    Passed,
    Failed,
    /// Not evaluated (disabled, or an earlier check made it impossible).
    NotRun,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct JwtSvidCheck {
    pub check: JwtSvidCheckKind,
    pub result: CheckResult,
    pub detail: String,
}

/// The JWT-SVID Anvil presented (decoded claims only, never the token).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct JwtSvidSummary {
    pub source: JwtSvidSourceKind,
    /// Audiences Anvil requested / required.
    pub requested_audiences: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub subject: Option<String>,
    /// The token's `aud` claim.
    pub audiences: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub algorithm: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub key_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub issued_at: Option<DateTime<Utc>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub not_before: Option<DateTime<Utc>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<DateTime<Utc>>,
    /// The token carries an `iss` claim (JWT-SVIDs define none).
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub has_issuer: bool,
    pub checks: Vec<JwtSvidCheck>,
    /// The token was sent although a check failed (explicit profile choice).
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub sent_despite_failed_checks: bool,
}

impl JwtSvidSummary {
    pub fn failed_checks(&self) -> impl Iterator<Item = &JwtSvidCheck> {
        self.checks.iter().filter(|c| c.result == CheckResult::Failed)
    }

    pub fn check(&self, kind: JwtSvidCheckKind) -> Option<&JwtSvidCheck> {
        self.checks.iter().find(|c| c.check == kind)
    }
}

/// Everything the Workload API contributed to one execution.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize, JsonSchema)]
pub struct WorkloadApiEvidence {
    pub calls: Vec<WorkloadApiCall>,
    pub x509_svids: Vec<X509SvidSummary>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub jwt_svid: Option<JwtSvidSummary>,
}

impl WorkloadApiEvidence {
    pub fn is_empty(&self) -> bool {
        self.calls.is_empty() && self.x509_svids.is_empty() && self.jwt_svid.is_none()
    }

    /// The last call that did not succeed.
    pub fn failed_call(&self) -> Option<&WorkloadApiCall> {
        self.calls.iter().rev().find(|c| c.result != WorkloadCallResult::Ok)
    }
}

/// gRPC status code names (the codes the Workload API can answer with).
pub fn grpc_code_name(code: i32) -> &'static str {
    match code {
        0 => "OK",
        1 => "CANCELLED",
        2 => "UNKNOWN",
        3 => "INVALID_ARGUMENT",
        4 => "DEADLINE_EXCEEDED",
        5 => "NOT_FOUND",
        6 => "ALREADY_EXISTS",
        7 => "PERMISSION_DENIED",
        8 => "RESOURCE_EXHAUSTED",
        9 => "FAILED_PRECONDITION",
        10 => "ABORTED",
        11 => "OUT_OF_RANGE",
        12 => "UNIMPLEMENTED",
        13 => "INTERNAL",
        14 => "UNAVAILABLE",
        15 => "DATA_LOSS",
        16 => "UNAUTHENTICATED",
        _ => "UNRECOGNIZED",
    }
}
