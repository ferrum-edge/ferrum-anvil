//! Native evidence recorded by transport adapters.
//!
//! Every field here is something an adapter actually observed. A phase that
//! did not happen on this attempt (reused connection, IP literal, cleartext)
//! is recorded as `reused` / `not_applicable` — never as a zero duration.

use crate::Id;
use crate::assertions::AssertionResult;
use crate::diagnostics::DiagnosticFinding;
use crate::outcome::ExecutionOutcome;
use crate::request::Protocol;
use crate::settings::EffectiveSettings;
use chrono::{DateTime, Utc};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum Phase {
    /// Local validation / preparation (variables, files, profiles, signing).
    Prepare,
    /// Waiting for a pooled connection or a concurrency slot.
    Queue,
    Dns,
    /// TCP connect (to the destination, or to the configured proxy).
    Connect,
    /// Proxy tunnel establishment (HTTP CONNECT / SOCKS handshake).
    ProxyTunnel,
    TlsHandshake,
    QuicHandshake,
    DtlsHandshake,
    /// Protocol handshake above TLS (HTTP/2 preface, WebSocket upgrade, ...).
    ProtocolHandshake,
    RequestWrite,
    AwaitResponseHeaders,
    ResponseBody,
    /// Long-lived session (WebSocket / SSE / TCP / UDP / gRPC stream).
    Session,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum PhaseStatus {
    Completed,
    Failed,
    TimedOut,
    Canceled,
    /// Satisfied by a reused connection; no new measurement exists.
    Reused,
    /// Not part of this attempt (IP literal, cleartext, no body, ...).
    NotApplicable,
    /// Started but outcome unknown (e.g. the attempt was abandoned).
    Unknown,
}

/// A measured phase. Offsets are microseconds from attempt start on a
/// monotonic clock. Concurrent phases may overlap; do not sum them blindly.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct PhaseTiming {
    pub phase: Phase,
    pub status: PhaseStatus,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub start_us: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub end_us: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
}

impl PhaseTiming {
    pub fn duration_us(&self) -> Option<u64> {
        match (self.start_us, self.end_us) {
            (Some(s), Some(e)) if e >= s => Some(e - s),
            _ => None,
        }
    }
}

/// Whether request bytes of an attempt may have reached the peer.
///
/// Derived from typed transport state (bytes written to the socket, response
/// received, HTTP/2 `REFUSED_STREAM`, ...), never from error message text.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum DispatchState {
    /// No request bytes were written (failure before the request was sent), or
    /// the peer explicitly guaranteed non-processing (HTTP/2 REFUSED_STREAM).
    NotDispatched,
    /// The peer received the request (a response to it arrived).
    Sent,
    /// Bytes were written but no response was received; processing may have occurred.
    MayHaveBeenSent,
    Unknown,
}

impl DispatchState {
    /// Combine per-attempt states into a whole-request summary: if any attempt
    /// may have reached the peer, the whole request may have been processed.
    pub fn summarize(states: impl IntoIterator<Item = DispatchState>) -> DispatchState {
        let mut any = false;
        let mut result = DispatchState::NotDispatched;
        for s in states {
            any = true;
            result = match (result, s) {
                (DispatchState::Sent, _) | (_, DispatchState::Sent) => DispatchState::Sent,
                (DispatchState::MayHaveBeenSent, _) | (_, DispatchState::MayHaveBeenSent) => DispatchState::MayHaveBeenSent,
                (DispatchState::Unknown, _) | (_, DispatchState::Unknown) => DispatchState::Unknown,
                _ => DispatchState::NotDispatched,
            };
        }
        if any { result } else { DispatchState::NotDispatched }
    }
}

/// Typed failure kinds. Rules match on these, never on message text.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum FailureKind {
    // ---- local preparation (nothing was sent) ----
    InvalidUrl,
    UnsupportedScheme,
    UnresolvedVariable,
    VariableCycle,
    MissingAttachment,
    ClientIdentityInvalid,
    ClientIdentityKeyMismatch,
    TlsProfileInvalid,
    ProxyConfigInvalid,
    InvalidHeader,
    BodySerialization,
    LintBlocked,
    RequestTooLargeLocal,
    AuthPreparationFailed,
    UnsupportedCombination,
    VaultLocked,
    // ---- name resolution (client leg) ----
    DnsNoSuchHost,
    DnsNoRecords,
    DnsTimeout,
    DnsServerFailure,
    DnsOther,
    // ---- TCP connect ----
    ConnectRefused,
    ConnectTimeout,
    ConnectReset,
    NetworkUnreachable,
    HostUnreachable,
    AddressUnavailable,
    ConnectOther,
    // ---- forward proxy ----
    ProxyConnectFailed,
    ProxyTunnelRejected,
    ProxyAuthRequired,
    ProxyProtocolError,
    // ---- TLS (client ↔ peer) ----
    TlsUntrustedIssuer,
    TlsExpired,
    TlsNotYetValid,
    TlsNameMismatch,
    TlsRevoked,
    TlsBadCertificate,
    TlsAlertReceived,
    TlsHandshakeTimeout,
    TlsPeerClosed,
    TlsReset,
    TlsProtocolMismatch,
    TlsAlpnMismatch,
    TlsOther,
    /// Peer sent a fatal alert after the client finished its handshake
    /// (TLS 1.3 client-certificate rejection surfaces here).
    TlsAlertAfterHandshake,
    // ---- QUIC / HTTP/3 ----
    QuicHandshakeTimeout,
    QuicIdleTimeout,
    QuicTransportError,
    QuicApplicationClosed,
    QuicOther,
    // ---- DTLS ----
    DtlsHandshakeTimeout,
    DtlsHandshakeFailed,
    // ---- request / response exchange ----
    RequestWriteTimeout,
    RequestWriteFailed,
    ResponseHeadersTimeout,
    ClosedBeforeResponse,
    ResetBeforeResponse,
    HttpProtocolError,
    H2StreamReset,
    H2RefusedStream,
    H2GoAway,
    ResponseHeadersTooLarge,
    // ---- response body ----
    BodyIdleTimeout,
    BodyIncomplete,
    BodyReset,
    ResponseTooLargeLocal,
    DecompressionFailed,
    // ---- sessions ----
    WsHandshakeRejected,
    WsProtocolError,
    WsMessageTooLarge,
    // ---- whole-attempt ----
    TotalTimeout,
    Canceled,
    Internal,
}

impl FailureKind {
    /// Failures that happened before any network activity for this attempt.
    pub fn is_local_preparation(self) -> bool {
        use FailureKind::*;
        matches!(
            self,
            InvalidUrl
                | UnsupportedScheme
                | UnresolvedVariable
                | VariableCycle
                | MissingAttachment
                | ClientIdentityInvalid
                | ClientIdentityKeyMismatch
                | TlsProfileInvalid
                | ProxyConfigInvalid
                | InvalidHeader
                | BodySerialization
                | LintBlocked
                | RequestTooLargeLocal
                | AuthPreparationFailed
                | UnsupportedCombination
                | VaultLocked
        )
    }

    pub fn is_tls_verification(self) -> bool {
        use FailureKind::*;
        matches!(self, TlsUntrustedIssuer | TlsExpired | TlsNotYetValid | TlsNameMismatch | TlsRevoked | TlsBadCertificate)
    }
}

/// A typed transport failure with library detail for display. `message` is
/// sanitized display text only; diagnostic rules must use the typed fields.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct TransportFailure {
    pub phase: Phase,
    pub kind: FailureKind,
    pub message: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub io_error_kind: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub os_error_code: Option<i32>,
    /// TLS alert description (e.g. `certificate_required`) when one was received.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tls_alert: Option<String>,
    /// HTTP/2 error code (RST_STREAM / GOAWAY) when applicable.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub h2_error_code: Option<u32>,
    /// QUIC transport/application error code when applicable.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub quic_error_code: Option<u64>,
    /// HTTP status of a rejected proxy CONNECT / WebSocket handshake.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub status: Option<u16>,
    /// Field path for local validation failures (e.g. `headers[2].value`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub field: Option<String>,
    /// The configured deadline that elapsed, for timeouts.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub deadline_ms: Option<u64>,
}

impl TransportFailure {
    pub fn new(phase: Phase, kind: FailureKind, message: impl Into<String>) -> Self {
        TransportFailure {
            phase,
            kind,
            message: message.into(),
            io_error_kind: None,
            os_error_code: None,
            tls_alert: None,
            h2_error_code: None,
            quic_error_code: None,
            status: None,
            field: None,
            deadline_ms: None,
        }
    }

    pub fn with_field(mut self, field: impl Into<String>) -> Self {
        self.field = Some(field.into());
        self
    }

    pub fn with_deadline(mut self, ms: Option<u64>) -> Self {
        self.deadline_ms = ms;
        self
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct CertificateSummary {
    pub subject: String,
    pub issuer: String,
    pub subject_alt_names: Vec<String>,
    pub not_before: String,
    pub not_after: String,
    pub serial_hex: String,
    pub sha256_fingerprint: String,
    pub is_ca: bool,
    pub key_algorithm: String,
}

/// Result of peer-certificate verification.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "result", rename_all = "snake_case")]
pub enum TlsVerification {
    Verified,
    Failed {
        problem: FailureKind,
        detail: String,
    },
    /// Verification disabled by an explicit, scoped bypass. Records what strict
    /// verification would have concluded.
    Bypassed {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        would_have_failed: Option<FailureKind>,
    },
    /// Handshake did not reach certificate verification.
    NotReached,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct TlsObservation {
    /// SNI/verification name used.
    pub server_name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cipher_suite: Option<String>,
    /// ALPN protocols offered by the client.
    pub alpn_offered: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub alpn_negotiated: Option<String>,
    pub verification: TlsVerification,
    /// Peer chain as presented (leaf first), when received.
    pub peer_certificates: Vec<CertificateSummary>,
    /// Whether the peer sent a CertificateRequest. `None` = not observed
    /// (handshake did not get that far, or resumed session).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub client_certificate_requested: Option<bool>,
    /// The client certificate actually presented (public data only).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub client_certificate_presented: Option<CertificateSummary>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub alert_received: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resumed: Option<bool>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct ConnectAttempt {
    pub address: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub failure: Option<FailureKind>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub duration_us: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct ConnectionObservation {
    /// Engine-local connection id (stable within one app session).
    pub id: u64,
    pub reused: bool,
    /// Negotiated application protocol: `http/1.1`, `h2`, `h3`, `ws`, `tcp`, `udp`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub protocol: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub local_address: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub remote_address: Option<String>,
    pub resolved_addresses: Vec<String>,
    /// Source of the addresses: `system`, `custom_resolver`, `override`, `literal`, `proxy`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resolution_source: Option<String>,
    pub connect_attempts: Vec<ConnectAttempt>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub via_proxy: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tls: Option<TlsObservation>,
    /// Requests previously served on this connection (0 = fresh).
    pub prior_requests: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "reason", rename_all = "snake_case")]
pub enum AttemptReason {
    Initial,
    Redirect { status: u16 },
    Retry { after: FailureKind },
    ProtocolFallback { from: String },
    AuthChallenge { scheme: String },
}

/// Byte accounting for one attempt. Logical header sizes on HTTP/2/3 are
/// estimates (HPACK/QPACK compress headers); `connection_*` counters are
/// connection-scoped TLS/transport bytes and include other multiplexed streams.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema, Default)]
pub struct ByteCounts {
    pub request_headers_logical: u64,
    pub request_headers_estimated: bool,
    pub request_body: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub response_headers_logical: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub response_body_wire: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub response_body_decoded: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub connection_bytes_written: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub connection_bytes_read: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct AttemptObservation {
    pub index: u32,
    pub reason: AttemptReason,
    pub method: String,
    /// Redacted URL.
    pub url: String,
    pub started_at: DateTime<Utc>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub connection: Option<ConnectionObservation>,
    pub phases: Vec<PhaseTiming>,
    pub dispatch: DispatchState,
    pub bytes: ByteCounts,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub response_status: Option<u16>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub failure: Option<TransportFailure>,
    pub duration_us: u64,
}

impl AttemptObservation {
    pub fn phase(&self, phase: Phase) -> Option<&PhaseTiming> {
        self.phases.iter().rev().find(|p| p.phase == phase)
    }
}

/// Header entry (order and duplicates preserved).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct HeaderEntry {
    pub name: String,
    pub value: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum BodyCompleteness {
    /// Framing completed normally (content-length satisfied, final chunk, END_STREAM).
    Complete,
    /// The stream ended abnormally before framing completed.
    Incomplete,
    /// The user or a deadline canceled reading.
    Canceled,
    /// Reading stopped at the local `max_response_bytes` ceiling.
    StoppedAtLocalLimit,
    /// No body by protocol (HEAD, 204, 304, 1xx).
    NoBody,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct BodyCapture {
    pub completeness: BodyCompleteness,
    /// Body bytes received from the wire (after transfer decoding, before content decoding).
    pub wire_bytes: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub declared_length: Option<u64>,
    /// Bytes retained for display/history.
    pub captured_bytes: u64,
    /// True when more bytes were received than retained (display cap only —
    /// NOT a wire failure).
    pub display_truncated: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub content_type: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub content_encoding: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub decoded_bytes: Option<u64>,
    /// Content-addressed id of the stored raw (captured) bytes.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub blob_sha256: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct ResponseRecord {
    pub status: u16,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    pub http_version: String,
    pub headers: Vec<HeaderEntry>,
    pub trailers: Vec<HeaderEntry>,
    pub trailers_received: bool,
    pub body: BodyCapture,
}

impl ResponseRecord {
    /// All values of a header (case-insensitive), in order.
    pub fn header_values<'a>(&'a self, name: &str) -> Vec<&'a str> {
        self.headers.iter().filter(|h| h.name.eq_ignore_ascii_case(name)).map(|h| h.value.as_str()).collect()
    }

    pub fn trailer_values<'a>(&'a self, name: &str) -> Vec<&'a str> {
        self.trailers.iter().filter(|h| h.name.eq_ignore_ascii_case(name)).map(|h| h.value.as_str()).collect()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum Direction {
    Sent,
    Received,
}

/// One message/event/datagram in a session transcript (bounded preview).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct StreamMessage {
    pub direction: Direction,
    pub offset_us: u64,
    /// `text`, `binary`, `ping`, `pong`, `close`, `event`, `grpc_message`, `datagram`, `bytes`.
    pub kind: String,
    pub size: u64,
    /// UTF-8 preview or hex (bounded).
    pub preview: String,
    pub preview_is_hex: bool,
    pub preview_truncated: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub event_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub event_type: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema, Default)]
pub struct StreamTranscript {
    pub messages: Vec<StreamMessage>,
    /// Messages dropped from the transcript because of the retention bound.
    pub dropped_messages: u64,
    pub sent_count: u64,
    pub received_count: u64,
    pub sent_bytes: u64,
    pub received_bytes: u64,
}

/// Summary of the prepared request as it was actually sent (redacted).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct PreparedSummary {
    pub protocol: Protocol,
    pub method: String,
    pub url: String,
    pub headers: Vec<HeaderEntry>,
    pub body_bytes: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub body_sha256: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub content_type: Option<String>,
    /// `api_key(header X-API-Key)`, `mtls(CN=...)`, etc. Never the secret.
    pub auth_label: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tls_profile: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub proxy: Option<String>,
    pub tls_verification_enabled: bool,
    pub settings: EffectiveSettings,
    /// Headers Anvil added or inferred, and why.
    pub inferred: Vec<String>,
    /// Secrets omitted from this summary (labels only).
    pub omitted_secrets: Vec<String>,
}

/// Complete record of one execution (possibly several attempts).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct ExecutionRecord {
    pub id: Id,
    pub schema_version: u32,
    pub adapter_version: String,
    pub catalog_version: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub compatibility_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub workspace_id: Option<Id>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub request_id: Option<Id>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub revision_id: Option<Id>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub environment_id: Option<Id>,
    pub started_at: DateTime<Utc>,
    pub finished_at: DateTime<Utc>,
    pub prepared: PreparedSummary,
    pub attempts: Vec<AttemptObservation>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub response: Option<ResponseRecord>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub stream: Option<StreamTranscript>,
    pub outcome: ExecutionOutcome,
    pub assertion_results: Vec<AssertionResult>,
    /// Extracted variable names (values are run-local and not persisted here).
    pub extracted: Vec<String>,
    pub findings: Vec<DiagnosticFinding>,
}
