use crate::Id;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

/// Protocol negotiation policy for HTTP-family requests.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema, Default)]
#[serde(rename_all = "snake_case")]
pub enum HttpVersionPolicy {
    /// ALPN negotiation over TLS (h2, then http/1.1); HTTP/1.1 for cleartext.
    #[default]
    Auto,
    Http1Only,
    /// HTTP/2 over TLS (ALPN `h2` only — fails rather than silently using HTTP/1.1).
    Http2Only,
    /// Cleartext HTTP/2 with prior knowledge.
    H2c,
    /// Forced HTTP/3 over QUIC. Never silently sends over TCP.
    Http3Only,
    /// Try HTTP/3 first, then fall back to TCP; every attempt is recorded.
    Http3WithFallback,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema, Default)]
#[serde(rename_all = "snake_case")]
pub enum IpPreference {
    #[default]
    System,
    PreferIpv4,
    PreferIpv6,
    Ipv4Only,
    Ipv6Only,
}

/// Separate timeout classes. `None` means "no deadline for this phase" (the
/// total deadline still applies). Values are milliseconds.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
pub struct Timeouts {
    pub dns_ms: Option<u64>,
    pub connect_ms: Option<u64>,
    pub tls_handshake_ms: Option<u64>,
    /// Deadline for handing the complete request (headers + body) to the connection.
    pub request_write_ms: Option<u64>,
    /// Deadline from request sent to response headers.
    pub response_headers_ms: Option<u64>,
    /// Maximum idle gap between response body chunks.
    pub body_idle_ms: Option<u64>,
    /// Whole-attempt deadline.
    pub total_ms: Option<u64>,
}

impl Default for Timeouts {
    fn default() -> Self {
        Timeouts {
            dns_ms: Some(5_000),
            connect_ms: Some(10_000),
            tls_handshake_ms: Some(10_000),
            request_write_ms: Some(30_000),
            response_headers_ms: Some(30_000),
            body_idle_ms: Some(30_000),
            total_ms: Some(120_000),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
pub struct RedirectPolicy {
    pub follow: bool,
    pub max: u8,
    /// Forward `Authorization`/cookies/client identity to a different origin.
    /// Off by default; the target's own configuration applies otherwise.
    pub forward_credentials_cross_origin: bool,
}

impl Default for RedirectPolicy {
    fn default() -> Self {
        RedirectPolicy { follow: true, max: 10, forward_credentials_cross_origin: false }
    }
}

/// Automatic retry policy. Off by default. Possibly-processed non-idempotent
/// operations are never retried automatically regardless of this setting.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema, Default)]
pub struct RetryPolicy {
    pub max_retries: u8,
    pub backoff_ms: u64,
    /// Retained for compatibility. Retries are always limited to failures
    /// proven `not_dispatched` or idempotent methods; a possibly processed
    /// non-idempotent request is never replayed, whatever this says.
    pub only_safe: bool,
}

/// TLS 1.3 / QUIC 0-RTT early data (RFC 8446 §2.3, RFC 9001 §4.6) with the
/// RFC 8470 semantics. Off by default: data sent before the handshake
/// completes can be replayed by anyone on the path, so only requests that are
/// safe to repeat may use it.
///
/// With `enabled`, a request whose method is eligible (GET, HEAD, OPTIONS, and
/// the idempotent methods listed in `extra_methods`) is sent as early data on
/// a new connection that resumes an earlier session of the same workspace, TLS
/// profile, client identity, server name and port. Any other method is sent
/// normally, after the handshake, and the record says why early data was not
/// used. A non-idempotent method in `extra_methods` is refused before traffic.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema, Default)]
pub struct EarlyDataPolicy {
    pub enabled: bool,
    /// Idempotent methods allowed in early data besides GET, HEAD and OPTIONS
    /// (`PUT`, `DELETE`, `TRACE`). Only an explicit choice adds them.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub extra_methods: Vec<String>,
}

impl EarlyDataPolicy {
    /// Methods that are always eligible when early data is enabled (safe, RFC 9110 §9.2.1).
    pub const DEFAULT_METHODS: &'static [&'static str] = &["GET", "HEAD", "OPTIONS"];
    /// Idempotent methods (RFC 9110 §9.2.2) a user may add explicitly.
    pub const ALLOWED_EXTRA_METHODS: &'static [&'static str] = &["PUT", "DELETE", "TRACE"];

    /// Whether `method` may be sent as early data under this policy (the
    /// policy's own validity is checked separately).
    pub fn allows(&self, method: &str) -> bool {
        let m = method.trim();
        self.enabled
            && (Self::DEFAULT_METHODS.iter().any(|d| d.eq_ignore_ascii_case(m))
                || self
                    .extra_methods
                    .iter()
                    .any(|x| x.trim().eq_ignore_ascii_case(m) && Self::ALLOWED_EXTRA_METHODS.iter().any(|a| a.eq_ignore_ascii_case(m))))
    }

    /// The first listed method that may never be sent as early data (not idempotent), if any.
    pub fn invalid_extra_method(&self) -> Option<&str> {
        self.extra_methods.iter().map(|m| m.trim()).find(|m| {
            !Self::DEFAULT_METHODS.iter().any(|d| d.eq_ignore_ascii_case(m))
                && !Self::ALLOWED_EXTRA_METHODS.iter().any(|a| a.eq_ignore_ascii_case(m))
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
pub struct DnsOverride {
    /// Host name to override (exact, case-insensitive).
    pub host: String,
    /// Addresses to connect to instead of resolving.
    pub addresses: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema, Default)]
#[serde(tag = "mode", rename_all = "snake_case")]
pub enum ResolverMode {
    /// Operating-system resolver (getaddrinfo).
    #[default]
    System,
    /// Query the given DNS servers directly (`ip:port`), bypassing the OS resolver.
    Custom { nameservers: Vec<String> },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
pub struct Limits {
    /// Hard ceiling on response body bytes read from the wire; exceeded bodies
    /// end with a local `response_too_large` outcome (never a peer fault).
    pub max_response_bytes: u64,
    /// Bytes retained for display/history; beyond this the body is still read
    /// and counted but marked display-truncated.
    pub capture_bytes: u64,
    /// Ceiling on decompressed size.
    pub max_decoded_bytes: u64,
    pub max_response_header_bytes: u64,
    pub max_request_body_bytes: u64,
}

impl Default for Limits {
    fn default() -> Self {
        Limits {
            max_response_bytes: 256 * 1024 * 1024,
            capture_bytes: 8 * 1024 * 1024,
            max_decoded_bytes: 64 * 1024 * 1024,
            max_response_header_bytes: 256 * 1024,
            max_request_body_bytes: 512 * 1024 * 1024,
        }
    }
}

/// Non-secret request settings resolved deterministically:
/// app defaults → workspace → ancestor folders → request → run override.
/// Every field is optional at each layer; `None` inherits.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema, Default)]
pub struct SettingsOverrides {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub http_version: Option<HttpVersionPolicy>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub timeouts: Option<TimeoutOverrides>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub redirects: Option<RedirectPolicy>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub retries: Option<RetryPolicy>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ip_preference: Option<IpPreference>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resolver: Option<ResolverMode>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub dns_overrides: Vec<DnsOverride>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub proxy_profile_id: Option<ProxySelection>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tls_profile_id: Option<Id>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub limits: Option<Limits>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub decompress: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cookies: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub keepalive: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub infer_content_type: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub integration_profile_id: Option<Id>,
    /// TLS 1.3 / QUIC 0-RTT early data (off unless a layer enables it).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub early_data: Option<EarlyDataPolicy>,
}

/// Partial timeout overrides (each class independently inheritable).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema, Default)]
pub struct TimeoutOverrides {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dns_ms: Option<Option<u64>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub connect_ms: Option<Option<u64>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tls_handshake_ms: Option<Option<u64>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub request_write_ms: Option<Option<u64>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub response_headers_ms: Option<Option<u64>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub body_idle_ms: Option<Option<u64>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub total_ms: Option<Option<u64>>,
}

/// Explicit proxy choice: a profile, or explicitly none (overrides inherited).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum ProxySelection {
    None,
    Profile { id: Id },
}

/// Fully-resolved settings used for one execution, with the layer each value
/// came from (for the Effective Request inspector).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct EffectiveSettings {
    pub http_version: HttpVersionPolicy,
    pub timeouts: Timeouts,
    pub redirects: RedirectPolicy,
    pub retries: RetryPolicy,
    pub ip_preference: IpPreference,
    pub resolver: ResolverMode,
    pub dns_overrides: Vec<DnsOverride>,
    pub proxy_profile_id: Option<Id>,
    pub tls_profile_id: Option<Id>,
    pub limits: Limits,
    pub decompress: bool,
    pub cookies: bool,
    pub keepalive: bool,
    pub infer_content_type: bool,
    pub integration_profile_id: Option<Id>,
    /// 0-RTT early data policy (records written before it existed load as off).
    #[serde(default)]
    pub early_data: EarlyDataPolicy,
    /// Field path → layer label ("app", "workspace", "folder:<name>", "request", "run").
    pub sources: Vec<SettingSource>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct SettingSource {
    pub field: String,
    pub layer: String,
}

impl Default for EffectiveSettings {
    fn default() -> Self {
        EffectiveSettings {
            http_version: HttpVersionPolicy::Auto,
            timeouts: Timeouts::default(),
            redirects: RedirectPolicy::default(),
            retries: RetryPolicy::default(),
            ip_preference: IpPreference::System,
            resolver: ResolverMode::System,
            dns_overrides: vec![],
            proxy_profile_id: None,
            tls_profile_id: None,
            limits: Limits::default(),
            decompress: true,
            cookies: true,
            keepalive: true,
            infer_content_type: true,
            integration_profile_id: None,
            early_data: EarlyDataPolicy::default(),
            sources: vec![],
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema, Default)]
#[serde(rename_all = "snake_case")]
pub enum Theme {
    #[default]
    System,
    Light,
    Dark,
}

/// What happens to active runs when the vault locks.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema, Default)]
#[serde(rename_all = "snake_case")]
pub enum LockRunPolicy {
    /// Cancel active sends/loads and finalize partial reports (default).
    #[default]
    StopRuns,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct HistoryPolicy {
    pub enabled: bool,
    pub keep_response_bodies: bool,
    pub max_age_days: u32,
    pub max_total_bytes: u64,
}

impl Default for HistoryPolicy {
    fn default() -> Self {
        HistoryPolicy { enabled: true, keep_response_bodies: true, max_age_days: 30, max_total_bytes: 512 * 1024 * 1024 }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct LockPolicy {
    /// Lock after this many minutes of inactivity (0 = never).
    pub idle_minutes: u32,
    pub lock_on_os_lock: bool,
    pub run_policy: LockRunPolicy,
    pub clear_clipboard_on_lock: bool,
}

impl Default for LockPolicy {
    fn default() -> Self {
        LockPolicy { idle_minutes: 15, lock_on_os_lock: true, run_policy: LockRunPolicy::StopRuns, clear_clipboard_on_lock: true }
    }
}

/// Portable application settings (included in whole-app backups).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct AppSettings {
    pub schema_version: u32,
    pub defaults: SettingsOverrides,
    pub theme: Theme,
    pub history: HistoryPolicy,
    pub lock: LockPolicy,
    pub autosave: bool,
    /// Extra header/query/cookie/body-field names always treated as secrets
    /// by the redactor (in addition to built-in patterns).
    pub redaction_names: Vec<String>,
    pub check_for_updates: bool,
}

impl Default for AppSettings {
    fn default() -> Self {
        AppSettings {
            schema_version: crate::SCHEMA_VERSION,
            defaults: SettingsOverrides::default(),
            theme: Theme::System,
            history: HistoryPolicy::default(),
            lock: LockPolicy::default(),
            autosave: false,
            redaction_names: vec![],
            check_for_updates: false,
        }
    }
}
