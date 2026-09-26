use crate::execution::{BodyCompleteness, DispatchState};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

/// Transport completion, independent of HTTP/RPC status.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum TransportState {
    /// The exchange completed at the transport level (full response framing).
    Completed,
    /// The exchange failed before a response was received.
    Failed,
    Canceled,
    /// A response started but did not complete (headers then truncated body,
    /// missing gRPC terminal status, abnormal stream end).
    Incomplete,
    Unknown,
}

/// Application-level result: HTTP status class, gRPC status, SOAP fault,
/// GraphQL errors. Evaluated only when a response exists.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ApplicationState {
    Success,
    Failure,
    NotEvaluated,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum AssertionState {
    Pass,
    Fail,
    NotRun,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum WarningCode {
    DegradedRouting,
    InsecureTls,
    PartialVisibility,
    DisplayTruncated,
    LintBypassed,
    UnverifiedFerrumMarker,
    CredentialsStrippedOnRedirect,
    ProtocolFallback,
    ReusedConnection,
    ClockSkewSuspected,
    ResponseIsUntrustedContent,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct OutcomeWarning {
    pub code: WarningCode,
    pub message: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum GrpcStatusSource {
    /// Status delivered in HTTP trailers.
    Trailers,
    /// Status delivered in response headers (trailers-only response).
    TrailersOnly,
    /// gRPC-Web: status delivered in the trailer frame (flag `0x80`) at the
    /// end of the response body.
    TrailerFrame,
    /// No terminal status was received — the RPC result is unknown.
    Missing,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ClosedBy {
    Peer,
    Client,
    /// Connection ended without a closing handshake (e.g. WebSocket 1006).
    Abnormal,
    Timeout,
    NotClosed,
}

/// Typed protocol-level result.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "protocol", rename_all = "snake_case")]
pub enum ProtocolStatus {
    None,
    Http {
        status: u16,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        reason: Option<String>,
    },
    Grpc {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        http_status: Option<u16>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        grpc_status: Option<i32>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        grpc_message: Option<String>,
        source: GrpcStatusSource,
    },
    #[serde(rename = "websocket")]
    WebSocket {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        handshake_status: Option<u16>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        close_code: Option<u16>,
        #[serde(default, skip_serializing_if = "String::is_empty")]
        close_reason: String,
        closed_by: ClosedBy,
        /// Extension negotiation and compression, when an extension was
        /// offered or answered, or a frame claimed one.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        extensions: Option<WsExtensions>,
    },
    Sse {
        http_status: u16,
        events: u64,
        closed_by: ClosedBy,
    },
    Tcp {
        bytes_sent: u64,
        bytes_received: u64,
        half_closed: bool,
        closed_by: ClosedBy,
    },
    Udp {
        datagrams_sent: u64,
        datagrams_received: u64,
        window_ms: u64,
        /// Present when the datagrams went through an RFC 9298 CONNECT-UDP
        /// (MASQUE) proxy.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        masque: Option<MasqueTunnel>,
    },
}

/// How HTTP Datagrams travelled through a CONNECT-UDP tunnel.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum MasqueEncoding {
    /// QUIC DATAGRAM frames (quarter stream ID + context ID 0).
    QuicDatagram,
    /// RFC 9297 DATAGRAM capsules on the CONNECT stream.
    Capsule,
}

/// Evidence about an RFC 9298 CONNECT-UDP tunnel through an HTTP/3 proxy.
/// Counts cover only what Anvil sent and received; delivery to the target
/// is never inferred.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct MasqueTunnel {
    /// `host:port` of the proxy.
    pub proxy: String,
    /// `host:port` the tunnel was requested for.
    pub target: String,
    /// Whether the proxy's HTTP/3 SETTINGS enabled extended CONNECT
    /// (`None`: no SETTINGS were received).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub extended_connect: Option<bool>,
    /// Whether HTTP/3 datagrams were available: the proxy's SETTINGS enabled
    /// `SETTINGS_H3_DATAGRAM` and QUIC negotiated DATAGRAM frames.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub h3_datagrams: Option<bool>,
    /// The proxy's HTTP status for the CONNECT-UDP request (`None`: no answer).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub connect_status: Option<u16>,
    /// The encoding chosen for sending (`None`: the tunnel never opened).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub encoding: Option<MasqueEncoding>,
    pub sent_quic_datagrams: u64,
    pub sent_capsules: u64,
    pub received_quic_datagrams: u64,
    pub received_capsules: u64,
    /// HTTP Datagrams with an unregistered context ID and capsules of
    /// unknown type, dropped as RFC 9298 §4 / RFC 9297 §3.1 require.
    #[serde(default)]
    pub dropped: u64,
    /// How the CONNECT stream (the tunnel) ended.
    pub closed_by: ClosedBy,
}

/// WebSocket extension negotiation (RFC 6455 §9) and RFC 7692
/// `permessage-deflate` evidence for one session.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct WsExtensions {
    /// The `Sec-WebSocket-Extensions` offer Anvil sent (absent: none).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub offered: Option<String>,
    /// The server's `Sec-WebSocket-Extensions` answer, verbatim and bounded
    /// (absent: the answer named no extension).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub answered: Option<String>,
    pub negotiation: WsNegotiation,
    /// Why the answer was refused (`negotiation = rejected`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub problem: Option<String>,
    /// The agreed parameters (`negotiation = negotiated`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub deflate: Option<WsDeflateParams>,
    /// Data messages of the session, before and after compression (absent
    /// when the session never opened).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub traffic: Option<WsCompressionTraffic>,
    /// A received frame broke the compression that was (or was not)
    /// negotiated, and Anvil ended the session.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub violation: Option<WsCompressionViolation>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum WsNegotiation {
    /// Nothing was offered and nothing was answered.
    NotOffered,
    /// Offered, but the answer named no extension: the session is uncompressed.
    NotNegotiated,
    /// `permessage-deflate` is in use.
    Negotiated,
    /// The answer did not fit the offer, or named an extension that was not
    /// offered; Anvil failed the handshake (RFC 6455 §4.1, RFC 7692 §7).
    Rejected,
}

/// Agreed `permessage-deflate` parameters (RFC 7692 §7.1).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct WsDeflateParams {
    pub server_no_context_takeover: bool,
    pub client_no_context_takeover: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub server_max_window_bits: Option<u8>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub client_max_window_bits: Option<u8>,
    /// Anvil compressed the messages it sent. False when the agreed client
    /// window is 2^8 bytes, which Anvil's DEFLATE cannot produce: it then
    /// sends uncompressed messages, which RFC 7692 §6 allows.
    pub client_compresses: bool,
}

/// Per-direction data-message totals of a WebSocket session.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct WsCompressionTraffic {
    pub sent: WsDirectionTotals,
    pub received: WsDirectionTotals,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema, Default)]
pub struct WsDirectionTotals {
    /// Text and binary messages whose first frame crossed the wire.
    pub messages: u64,
    /// Of those, messages with RSV1 set (compressed).
    pub compressed_messages: u64,
    /// Payload bytes of the complete messages, uncompressed (the sizes in
    /// the transcript).
    pub payload_bytes: u64,
    /// Data-frame payload bytes on the wire, as sent or received
    /// (compressed where RSV1 was set).
    pub wire_bytes: u64,
}

/// Why a received frame ended a session (all are the peer's frames).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum WsViolationKind {
    /// A data message arrived with RSV1 set although no compression was
    /// negotiated (RFC 6455 §5.2).
    CompressedWithoutNegotiation,
    /// A compressed message could not be decompressed (RFC 7692 §7.2.2).
    Undecodable,
    /// A compressed message grew past Anvil's local message limit while it
    /// was decompressed.
    TooLargeAfterDecompression,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct WsCompressionViolation {
    pub kind: WsViolationKind,
    /// Compressed bytes of the offending message received when it failed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub compressed_bytes: Option<u64>,
    /// Anvil's local message limit, in decompressed bytes.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub limit_bytes: Option<u64>,
    /// The decompressor's description of the problem.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
}

/// The composite outcome. Transport completion, application status and
/// assertion results are deliberately separate dimensions.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct ExecutionOutcome {
    pub transport: TransportState,
    pub application: ApplicationState,
    pub assertions: AssertionState,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub completeness: Option<BodyCompleteness>,
    pub protocol_status: ProtocolStatus,
    /// Summary across all attempts: whether the whole request may have been processed.
    pub dispatch: DispatchState,
    pub warnings: Vec<OutcomeWarning>,
    /// One-line human summary (derived; not authoritative).
    pub summary: String,
}
