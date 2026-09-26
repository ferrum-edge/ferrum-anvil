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
    /// X.509-SVID from the SPIFFE Workload API (`FetchX509SVID`), fetched
    /// when a request needs it and re-fetched at half its lifetime (SVID
    /// rotation). The private key stays in memory and is cleared on lock.
    WorkloadApi {
        /// `unix:///path/to/socket` (or `npipe:name` on Windows). Empty: the
        /// `SPIFFE_ENDPOINT_SOCKET` environment variable.
        #[serde(default, skip_serializing_if = "String::is_empty")]
        endpoint: String,
        /// Pick the SVID with this SPIFFE ID when the workload holds several.
        /// Empty: the first (default) SVID.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        spiffe_id: Option<String>,
        /// Also trust the SVID's trust-domain bundle from the Workload API
        /// (for verifying mesh peers by SPIFFE ID), in addition to the
        /// profile's CA certificates.
        #[serde(default)]
        trust_bundle: bool,
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
    /// Override the SNI / verification name (advanced). The HTTP authority is
    /// unchanged. The certificate is verified against this name, or against
    /// the SPIFFE identity when [`TlsProfile::server_spiffe`] is set. East-west
    /// SNI passthrough uses names like `outbound_.8080_._.svc.ns.svc.cluster.local`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub server_name_override: Option<String>,
    /// SPIFFE X.509-SVID server identity (mesh). When set, the peer chain is
    /// verified against this profile's trust anchors (its trust bundle) and
    /// the certificate's single `spiffe://` URI SAN is matched instead of the
    /// DNS host name. Unset (the default) keeps ordinary host-name verification.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub server_spiffe: Option<ServerSpiffeIdentity>,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub updated_at: chrono::DateTime<chrono::Utc>,
}

/// Expected SPIFFE identity of a TLS server (X.509-SVID). At least one field
/// must be set; when both are, the ID must belong to the trust domain.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize, JsonSchema)]
pub struct ServerSpiffeIdentity {
    /// Exact SPIFFE ID the server must present, e.g.
    /// `spiffe://cluster.local/ns/ferrum/sa/svc`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expected_server_spiffe_id: Option<String>,
    /// Trust domain the server's SPIFFE ID must belong to, e.g. `cluster.local`
    /// (any workload of that trust domain is accepted).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub trust_domain: Option<String>,
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
    /// Mesh HBONE endpoint (Ferrum Mesh / Istio ambient): HTTP/2 `CONNECT`
    /// over mutual TLS. Anvil presents the client SVID of the proxy's TLS
    /// profile, verifies the endpoint's server identity, then runs the inner
    /// connection over the tunnel stream.
    Hbone,
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
    /// TLS profile for the connection to the proxy itself: trust anchors,
    /// client identity (the client SVID for HBONE) and server identity
    /// (e.g. the endpoint's SPIFFE ID). Required for `hbone`; optional for
    /// `https` (default: system roots with strict verification).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tls_profile_id: Option<Id>,
    /// HBONE `CONNECT` options (kind `hbone` only).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hbone: Option<HboneOptions>,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub updated_at: chrono::DateTime<chrono::Utc>,
}

/// Optional protocol marker on the HBONE `CONNECT`. Istio ztunnel sends none;
/// Ferrum accepts either marker (value `hbone`) or none. A marker is a wire
/// shape hint only and never authenticates the peer.
///
/// A UDP request (`udp://`) through the profile always sends a marker with
/// the value `udp` (Ferrum Mesh datagram-over-HBONE): `x-istio-protocol:
/// udp` for [`HboneMarker::IstioProtocol`], `x-ferrum-mesh-protocol: udp`
/// otherwise.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema, Default)]
#[serde(rename_all = "snake_case")]
pub enum HboneMarker {
    #[default]
    None,
    /// `x-ferrum-mesh-protocol: hbone`
    FerrumMeshProtocol,
    /// `x-istio-protocol: hbone`
    IstioProtocol,
}

#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize, JsonSchema)]
pub struct HboneOptions {
    #[serde(default)]
    pub marker: HboneMarker,
    /// W3C `baggage` header value for the `CONNECT`, e.g.
    /// `source.principal=spiffe://cluster.local/ns/a/sa/b`. The endpoint honors
    /// identity baggage only from trusted assertors that match the client SVID.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub baggage: Option<String>,
    /// Additional `CONNECT` request headers (sent verbatim, in order).
    #[serde(default)]
    pub extra_headers: Vec<crate::request::KeyValue>,
}
