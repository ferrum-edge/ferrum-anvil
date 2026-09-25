use super::Ctx;
use crate::{Draft, warn};
use anvil_domain::diagnostics::{Confidence, EvidenceSource as E, Owner, Severity, SourceScope};
use anvil_domain::execution::FailureKind;
use anvil_domain::outcome::{ClosedBy, GrpcStatusSource, OutcomeWarning, ProtocolStatus, WarningCode};

pub fn grpc_name(code: i32) -> &'static str {
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

pub fn rules(ctx: &Ctx<'_>, out: &mut Vec<Draft>, warnings: &mut Vec<OutcomeWarning>) {
    let idx = ctx.attempt_index();
    if let Some(from) = &ctx.input.protocol_fallback_from {
        warn(warnings, WarningCode::ProtocolFallback, format!("{from} was attempted first; the final response used a different protocol."));
        out.push(
            Draft::new(
                "client.h3.fallback_used",
                "protocol.http3",
                Confidence::Confirmed,
                SourceScope::ClientToPeer,
                Owner::Unknown,
                Severity::Info,
            )
            .var("from", from.clone())
            .var(
                "to",
                ctx.final_attempt().and_then(|a| a.connection.as_ref()).and_then(|c| c.protocol.clone()).unwrap_or_else(|| "TCP".into()),
            ),
        );
    }
    match ctx.input.protocol_status {
        ProtocolStatus::Grpc { http_status, grpc_status, grpc_message, source } => match (grpc_status, source) {
            (Some(0), _) => {}
            (Some(code), src) => out.push(
                Draft::new("app.grpc_status", "protocol.grpc", Confidence::Confirmed, SourceScope::Unknown, Owner::ApiOwner, Severity::Error)
                    .ev_at(E::GrpcStatus, "grpc-status", code.to_string(), idx)
                    .ev_at(E::GrpcStatus, "grpc-message", grpc_message.clone().unwrap_or_default(), idx)
                    .ev_at(E::GrpcStatus, "status.source", format!("{src:?}"), idx)
                    .ev_at(E::HttpStatus, "http_status", http_status.map(|s| s.to_string()).unwrap_or_default(), idx)
                    .var("code", code.to_string())
                    .var("name", grpc_name(*code).to_string())
                    .var("message", grpc_message.clone().unwrap_or_default())
                    .var("http_status", http_status.map(|s| s.to_string()).unwrap_or_else(|| "no".into()))
                    .var(
                        "trailers_only",
                        if matches!(src, GrpcStatusSource::TrailersOnly) {
                            "The status arrived as a trailers-only response (no messages), which gateways and servers both use for early rejection.".into()
                        } else {
                            String::new()
                        },
                    ),
            ),
            (None, GrpcStatusSource::Missing) => {
                if http_status.is_some() {
                    out.push(
                        Draft::new("app.grpc_status_missing", "protocol.grpc", Confidence::Confirmed, SourceScope::ResponseDelivery, Owner::Unknown, Severity::Error)
                            .ev_at(E::GrpcStatus, "grpc-status", "missing", idx)
                            .var("http_status", http_status.map(|s| s.to_string()).unwrap_or_default()),
                    );
                }
            }
            _ => {}
        },
        ProtocolStatus::WebSocket { handshake_status, close_code, close_reason, closed_by } => {
            let base = |code: &str, conf: Confidence, owner: Owner, sev: Severity| {
                Draft::new(code, "protocol.websocket", conf, SourceScope::Unknown, owner, sev)
                    .ev_at(E::WebSocketClose, "close.code", close_code.map(|c| c.to_string()).unwrap_or_else(|| "none".into()), idx)
                    .ev_at(E::WebSocketClose, "close.reason", close_reason.clone(), idx)
                    .ev_at(E::WebSocketClose, "closed_by", format!("{closed_by:?}"), idx)
                    .var("code", close_code.map(|c| c.to_string()).unwrap_or_else(|| "none".into()))
                    .var("reason", close_reason.clone())
            };
            match (handshake_status, close_code, closed_by) {
                (Some(s), _, _) if *s != 101 && *s != 200 => out.push(
                    base("ws.handshake_rejected", Confidence::Confirmed, Owner::Unknown, Severity::Error)
                        .ev_at(E::HttpStatus, "status", s.to_string(), idx)
                        .var("status", s.to_string()),
                ),
                (_, Some(1000), _) | (_, Some(1001), _) => out.push(base("ws.closed_normally", Confidence::Confirmed, Owner::Unknown, Severity::Info)),
                (_, None, ClosedBy::Abnormal) | (_, Some(1006), _) => out.push(base("ws.closed_abnormally", Confidence::Confirmed, Owner::Unknown, Severity::Error)),
                (_, Some(1008), _) => out.push(base("ws.closed_policy", Confidence::Confirmed, Owner::Unknown, Severity::Error)),
                (_, Some(1009), _) => out.push(base("ws.closed_too_big", Confidence::Confirmed, Owner::Caller, Severity::Error)),
                (_, Some(_), ClosedBy::Peer) => out.push(base("ws.closed_other", Confidence::Confirmed, Owner::Unknown, Severity::Warning)),
                _ => {}
            }
        }
        ProtocolStatus::Sse { events, closed_by, .. } => {
            let canceled = ctx.final_attempt().and_then(|a| a.failure.as_ref()).map(|f| f.kind == FailureKind::Canceled).unwrap_or(false);
            if canceled || *closed_by == ClosedBy::Client {
                out.push(
                    Draft::new("sse.canceled", "protocol.streams", Confidence::Confirmed, SourceScope::LocalClient, Owner::Caller, Severity::Info)
                        .var("events", events.to_string()),
                );
            } else if *closed_by == ClosedBy::Timeout {
                out.push(
                    Draft::new("sse.idle_timeout", "protocol.streams", Confidence::Confirmed, SourceScope::ClientToPeer, Owner::Unknown, Severity::Warning)
                        .var("events", events.to_string()),
                );
            }
        }
        ProtocolStatus::Udp { datagrams_sent, datagrams_received, window_ms } => {
            if *datagrams_received == 0 && *datagrams_sent > 0 {
                out.push(
                    Draft::new("udp.no_response", "protocol.streams", Confidence::Confirmed, SourceScope::Unknown, Owner::Unknown, Severity::Warning)
                        .ev(E::NativeTransport, "udp.sent", datagrams_sent.to_string())
                        .ev(E::NativeTransport, "udp.received", "0")
                        .var("sent", datagrams_sent.to_string())
                        .var("window_ms", window_ms.to_string()),
                );
            } else if datagrams_received < datagrams_sent {
                out.push(
                    Draft::new("udp.partial_responses", "protocol.streams", Confidence::Confirmed, SourceScope::Unknown, Owner::Unknown, Severity::Info)
                        .var("sent", datagrams_sent.to_string())
                        .var("received", datagrams_received.to_string())
                        .var("window_ms", window_ms.to_string()),
                );
            }
        }
        ProtocolStatus::Tcp { bytes_received, half_closed, closed_by, .. } => {
            if *half_closed && *bytes_received > 0 {
                out.push(
                    Draft::new("tcp.reply_after_half_close", "protocol.streams", Confidence::Confirmed, SourceScope::ClientToPeer, Owner::Unknown, Severity::Info)
                        .var("bytes", bytes_received.to_string()),
                );
            }
            if *closed_by == ClosedBy::Abnormal {
                out.push(Draft::new("tcp.closed_abnormally", "protocol.streams", Confidence::Confirmed, SourceScope::ClientToPeer, Owner::Unknown, Severity::Error));
            }
        }
        _ => {}
    }
}
