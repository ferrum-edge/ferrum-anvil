use crate::Id;
use crate::secret::SensitiveValue;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema, Default)]
#[serde(rename_all = "snake_case")]
pub enum TlsMinVersion {
    #[default]
    Tls12,
    Tls13,
}

/// Client identity presented to a peer (identity #2 in the plan's three
/// identities). Never the gateway's own backend identity.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "format", rename_all = "snake_case")]
pub enum ClientIdentity {
    Pem {
        /// Certificate chain PEM (not secret).
        cert_chain_pem: String,
        /// Private key PEM (PKCS#8, PKCS#1 or SEC1) — sensitive.
        private_key_pem: SensitiveValue,
    },
    Pkcs12 {
        /// Base64 PKCS#12 bundle — sensitive.
        bundle_b64: SensitiveValue,
        password: SensitiveValue,
    },
}

/// Host/port pattern a TLS profile or client identity is bound to. Wildcards
/// are allowed only as a leading `*.` label and produce a UI warning.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
pub struct HostBinding {
    pub host: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub port: Option<u16>,
}

/// Trust + identity settings for TLS/DTLS connections.
///
/// `verify = false` means encryption stays on but the peer is not
/// authenticated. That is distinct from choosing plaintext (`http://`). A
/// bypass is scoped to the requests that select this profile, shows a
/// persistent warning, and is never activated by import.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct TlsProfile {
    pub id: Id,
    pub workspace_id: Id,
    pub name: String,
    #[serde(default = "default_true")]
    pub verify: bool,
    #[serde(default = "default_true")]
    pub use_system_roots: bool,
    /// Additional trusted CA certificates (PEM). Scoped to this profile only;
    /// never installed into the OS store.
    #[serde(default)]
    pub extra_roots_pem: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub client_identity: Option<ClientIdentity>,
    /// Destinations where this profile's client identity may be presented.
    /// Empty = any destination that selects the profile (UI warns).
    #[serde(default)]
    pub bindings: Vec<HostBinding>,
    #[serde(default)]
    pub min_version: TlsMinVersion,
    /// Override the SNI / verification name (advanced). The HTTP authority is unchanged.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub server_name_override: Option<String>,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub updated_at: chrono::DateTime<chrono::Utc>,
}

fn default_true() -> bool {
    true
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema, Default)]
#[serde(rename_all = "snake_case")]
pub enum ProxyKind {
    /// HTTP forward proxy (absolute-form for http://, CONNECT for https://).
    #[default]
    Http,
    /// HTTPS connection to the proxy itself, then CONNECT.
    Https,
    Socks5,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct ProxyProfile {
    pub id: Id,
    pub workspace_id: Id,
    pub name: String,
    pub kind: ProxyKind,
    /// `host:port` of the proxy.
    pub address: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub username: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub password: Option<SensitiveValue>,
    /// `NO_PROXY` semantics: comma-separated hosts/suffixes/CIDRs, `*` for all.
    #[serde(default)]
    pub no_proxy: String,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub updated_at: chrono::DateTime<chrono::Utc>,
}
