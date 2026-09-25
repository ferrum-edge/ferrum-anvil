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
    Trailers,
    /// Status delivered in response headers (trailers-only response).
    TrailersOnly,
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
    },
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
