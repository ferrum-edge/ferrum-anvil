use crate::Id;
use crate::secret::SensitiveValue;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

/// Where an API key is presented.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema, Default)]
#[serde(rename_all = "snake_case")]
pub enum KeyLocation {
    #[default]
    Header,
    Query,
    Cookie,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema, Default)]
pub enum JwtAlgorithm {
    #[default]
    HS256,
    HS384,
    HS512,
    RS256,
    ES256,
}

/// Claims editor for the JWT helper. Anvil signs only with key material the
/// user supplies; it never invents an issuer or a gateway token endpoint.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema, Default)]
pub struct JwtClaims {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub iss: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sub: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub aud: Option<String>,
    /// Lifetime in seconds from signing time; `exp` is computed per send.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires_in_secs: Option<i64>,
    /// `nbf` offset (seconds, may be negative) relative to signing time.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub not_before_offset_secs: Option<i64>,
    /// Additional claims as a JSON object text (may contain `{{vars}}`).
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub extra_json: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema, Default)]
#[serde(rename_all = "snake_case")]
pub enum OAuthGrant {
    #[default]
    ClientCredentials,
    /// Authorization code with PKCE (S256) through the external system browser
    /// and a loopback redirect bound to one authorization attempt.
    AuthorizationCodePkce,
    RefreshToken,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct OAuth2Config {
    pub grant: OAuthGrant,
    pub token_url: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub authorization_url: String,
    pub client_id: String,
    /// Confidential-client secret (client credentials). Public PKCE clients
    /// leave this empty.
    #[serde(default)]
    pub client_secret: SensitiveValue,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub scope: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub audience: String,
    /// How client credentials are sent to the token endpoint.
    #[serde(default)]
    pub client_auth: OAuthClientAuth,
    /// Where the acquired access token is cached (vault) — id of the token
    /// cache entry, managed by the engine.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub token_cache_id: Option<Id>,
    /// Refresh this many seconds before expiry.
    #[serde(default = "default_refresh_skew")]
    pub refresh_skew_secs: u32,
}

fn default_refresh_skew() -> u32 {
    30
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema, Default)]
#[serde(rename_all = "snake_case")]
pub enum OAuthClientAuth {
    #[default]
    BasicHeader,
    RequestBody,
}

/// HMAC request signing profile. `FerrumV2` is the gateway's current
/// single-use profile; `FerrumV1Legacy` is disabled unless the user explicitly
/// enables the unsafe compatibility option.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema, Default)]
#[serde(rename_all = "snake_case")]
pub enum HmacProfile {
    #[default]
    FerrumV2,
    FerrumV1Legacy,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema, Default)]
#[serde(rename_all = "snake_case")]
pub enum HmacAlgorithm {
    #[default]
    HmacSha256,
    HmacSha384,
    HmacSha512,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema, Default)]
#[serde(rename_all = "snake_case")]
pub enum BodyDigestHeader {
    /// RFC 9530 `Content-Digest: sha-256=:<b64>:`.
    #[default]
    ContentDigest,
    /// Legacy RFC 3230 `Digest: SHA-256=<b64>`.
    LegacyDigest,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct HmacConfig {
    #[serde(default)]
    pub profile: HmacProfile,
    pub username: String,
    pub secret: SensitiveValue,
    #[serde(default)]
    pub algorithm: HmacAlgorithm,
    #[serde(default)]
    pub digest_header: BodyDigestHeader,
    /// Optional namespace bound into the signature when the gateway profile uses one.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub namespace: String,
    /// Explicit opt-in required to use the replayable legacy profile.
    #[serde(default)]
    pub allow_unsafe_legacy: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct DpopConfig {
    /// The access token (bound to the proof key by the issuer).
    pub access_token: SensitiveValue,
    /// PKCS#8 PEM of the ES256 proof key (vault reference recommended).
    pub private_key_pem: SensitiveValue,
    /// Present the token as `DPoP <token>` (RFC 9449) or legacy `Bearer`.
    #[serde(default = "crate::request::default_true")]
    pub dpop_scheme: bool,
    /// Automatically answer a single `use_dpop_nonce` challenge with a fresh proof.
    #[serde(default = "crate::request::default_true")]
    pub handle_nonce_challenge: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema, Default)]
#[serde(rename_all = "snake_case")]
pub enum WssePasswordType {
    #[default]
    PasswordText,
    PasswordDigest,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct WsseConfig {
    pub username: String,
    pub password: SensitiveValue,
    #[serde(default)]
    pub password_type: WssePasswordType,
    /// Add a `wsu:Timestamp` with this lifetime.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub timestamp_ttl_secs: Option<u32>,
    /// User-provided signed SAML assertion XML to embed verbatim (Anvil never
    /// mints assertions).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub saml_assertion: Option<SensitiveValue>,
}

/// Auth configuration. Applied after interpolation, content-type inference
/// and serialization so body-dependent signatures cover the final bytes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema, Default)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum AuthConfig {
    /// Use the nearest ancestor folder/workspace auth.
    #[default]
    Inherit,
    /// Explicitly send no credentials (clears inherited auth).
    None,
    ApiKey {
        name: String,
        value: SensitiveValue,
        #[serde(default)]
        location: KeyLocation,
    },
    Basic {
        username: String,
        password: SensitiveValue,
    },
    Bearer {
        token: SensitiveValue,
        #[serde(default = "default_bearer_prefix")]
        prefix: String,
    },
    Jwt {
        algorithm: JwtAlgorithm,
        /// HMAC secret, or PKCS#8 PEM private key for RS/ES algorithms.
        signing_key: SensitiveValue,
        claims: JwtClaims,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        kid: Option<String>,
        /// Header carrying the token (default `Authorization: Bearer`).
        #[serde(default = "default_auth_header")]
        header_name: String,
        #[serde(default = "default_bearer_prefix")]
        prefix: String,
    },
    #[serde(rename = "oauth2")]
    OAuth2 {
        config: OAuth2Config,
    },
    Hmac {
        config: HmacConfig,
    },
    Dpop {
        config: DpopConfig,
    },
    /// SOAP WS-Security header inserted into the SOAP envelope.
    Wsse {
        config: WsseConfig,
    },
    /// SPIFFE JWT-SVID as a bearer credential, from the Workload API or a
    /// variable/file, checked locally before it is sent.
    JwtSvid {
        config: crate::workload::JwtSvidConfig,
    },
    /// Several explicit presentations in one request (e.g. mTLS + API key).
    /// Order is preserved; conflicting headers fail validation.
    Multi {
        profiles: Vec<AuthConfig>,
    },
}

fn default_bearer_prefix() -> String {
    "Bearer".into()
}
fn default_auth_header() -> String {
    "Authorization".into()
}

impl AuthConfig {
    pub fn kind_label(&self) -> &'static str {
        match self {
            AuthConfig::Inherit => "inherit",
            AuthConfig::None => "none",
            AuthConfig::ApiKey { .. } => "api_key",
            AuthConfig::Basic { .. } => "basic",
            AuthConfig::Bearer { .. } => "bearer",
            AuthConfig::Jwt { .. } => "jwt",
            AuthConfig::OAuth2 { .. } => "oauth2",
            AuthConfig::Hmac { .. } => "hmac",
            AuthConfig::Dpop { .. } => "dpop",
            AuthConfig::Wsse { .. } => "wsse",
            AuthConfig::JwtSvid { .. } => "jwt_svid",
            AuthConfig::Multi { .. } => "multi",
        }
    }
}
