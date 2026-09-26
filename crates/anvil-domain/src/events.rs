use crate::Id;
use crate::execution::{Direction, FailureKind, Phase, PhaseStatus, StreamMessage};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

/// Structured, bounded progress events emitted while an execution runs. The
/// UI and CLI render these live; the final [`crate::execution::ExecutionRecord`]
/// is authoritative.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "event", rename_all = "snake_case")]
pub enum ExecutionEvent {
    Started { execution_id: Id, method: String, url: String },
    AttemptStarted { execution_id: Id, attempt: u32 },
    Phase { execution_id: Id, attempt: u32, phase: Phase, status: PhaseStatus, offset_us: u64 },
    ResponseHead { execution_id: Id, attempt: u32, status: u16 },
    BodyProgress { execution_id: Id, bytes: u64 },
    Message { execution_id: Id, message: StreamMessage },
    AttemptFailed { execution_id: Id, attempt: u32, kind: FailureKind },
    Finished { execution_id: Id },
}

/// Commands for an interactive session (WebSocket / TCP / UDP / bidi gRPC).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "command", rename_all = "snake_case")]
pub enum SessionCommand {
    SendText { text: String },
    SendBinaryHex { hex: String },
    Ping,
    Close { code: u16, reason: String },
    HalfClose,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct SessionMessageEvent {
    pub session_id: Id,
    pub direction: Direction,
    pub message: StreamMessage,
}
