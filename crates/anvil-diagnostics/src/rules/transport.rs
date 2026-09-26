use super::Ctx;
use crate::{Draft, warn};
use anvil_domain::diagnostics::{Confidence, EvidenceSource as E, Owner, Severity, SourceScope};
use anvil_domain::execution::{BodyCompleteness, FailureKind as K, Phase};
use anvil_domain::outcome::{OutcomeWarning, WarningCode};

pub fn rules(ctx: &Ctx<'_>, out: &mut Vec<Draft>, warnings: &mut Vec<OutcomeWarning>) {
    let Some(a) = ctx.final_attempt() else { return };
    let host = ctx.target_host();

    if let Some(r) = ctx.input.response {
        if r.body.display_truncated && r.body.completeness == BodyCompleteness::Complete {
            warn(
                warnings,
                WarningCode::DisplayTruncated,
                format!(
                    "Only the first {} of {} response bytes were kept for display; the response itself completed normally.",
                    r.body.captured_bytes, r.body.wire_bytes
                ),
            );
        }
        if a.connection.as_ref().map(|c| c.reused).unwrap_or(false) {
            warn(
                warnings,
                WarningCode::ReusedConnection,
                "This request reused an existing connection; DNS, connect and TLS timings are not re-measured.",
            );
        }
    }

    let Some(f) = a.failure.as_ref() else { return };
    // The end of an HBONE datagram tunnel mid-session belongs to the tunnel's
    // stream, which the endpoint owns: the mesh rules explain it, and no
    // exchange finding may describe it as the destination's reset.
    let datagram_tunnel = a.connection.as_ref().and_then(|c| c.tunnel.as_ref()).is_some_and(|t| t.datagrams.is_some());
    if datagram_tunnel && f.phase == Phase::Session && !matches!(f.kind, K::TotalTimeout | K::Canceled) {
        return;
    }
    let status = a.response_status;
    let base = |code: &str, conf: Confidence, scope: SourceScope, owner: Owner, sev: Severity| {
        let mut d = Draft::new(code, "transport.exchange", conf, scope, owner, sev)
            .ev_at(E::NativeTransport, "failure.kind", format!("{:?}", f.kind), a.index)
            .ev_at(E::NativeTransport, "failure.phase", format!("{:?}", f.phase), a.index)
            .ev_at(E::NativeTransport, "dispatch", format!("{:?}", a.dispatch), a.index)
            .var("host", host.clone())
            .var("message", f.message.clone())
            .var("deadline_ms", f.deadline_ms.map(|d| d.to_string()).unwrap_or_else(|| "the configured".into()))
            .var("method", a.method.clone());
        if let Some(code) = f.h2_error_code {
            d = d.ev_at(E::NativeTransport, "h2.error_code", h2_name(code), a.index).var("h2_code", h2_name(code));
        }
        if let Some(s) = status {
            d = d.ev_at(E::HttpStatus, "status", s.to_string(), a.index).var("status", s.to_string());
        }
        d
    };
    let d = match f.kind {
        K::RequestWriteTimeout => {
            Some(base("exchange.write_timeout", Confidence::Confirmed, SourceScope::ClientToPeer, Owner::Unknown, Severity::Error))
        }
        K::RequestWriteFailed => {
            Some(base("exchange.write_failed", Confidence::Confirmed, SourceScope::ClientToPeer, Owner::Unknown, Severity::Error))
        }
        K::ResponseHeadersTimeout => {
            Some(base("exchange.headers_timeout", Confidence::Confirmed, SourceScope::ClientToPeer, Owner::Unknown, Severity::Error))
        }
        K::ClosedBeforeResponse => {
            Some(base("exchange.closed_before_response", Confidence::Confirmed, SourceScope::ClientToPeer, Owner::Unknown, Severity::Error))
        }
        K::ResetBeforeResponse => {
            Some(base("exchange.reset_before_response", Confidence::Confirmed, SourceScope::ClientToPeer, Owner::Unknown, Severity::Error))
        }
        K::HttpProtocolError if status.is_none() => {
            Some(base("exchange.protocol_error", Confidence::Confirmed, SourceScope::ClientToPeer, Owner::Unknown, Severity::Error))
        }
        K::ResponseHeadersTooLarge => {
            Some(base("exchange.headers_too_large", Confidence::Confirmed, SourceScope::ClientToPeer, Owner::Caller, Severity::Error))
        }
        K::H2RefusedStream => {
            Some(base("exchange.h2_refused_stream", Confidence::Confirmed, SourceScope::ClientToPeer, Owner::Unknown, Severity::Error))
        }
        K::H2StreamReset if status.is_none() => {
            Some(base("exchange.h2_stream_reset", Confidence::Confirmed, SourceScope::ClientToPeer, Owner::Unknown, Severity::Error))
        }
        K::H2GoAway if status.is_none() => {
            Some(base("exchange.h2_goaway", Confidence::Confirmed, SourceScope::ClientToPeer, Owner::Unknown, Severity::Error))
        }
        K::TotalTimeout if status.is_none() => {
            Some(base("exchange.total_timeout", Confidence::Confirmed, SourceScope::ClientToPeer, Owner::Caller, Severity::Error))
        }
        K::Canceled if status.is_none() => {
            Some(base("request.canceled", Confidence::Confirmed, SourceScope::LocalClient, Owner::Caller, Severity::Warning))
        }
        K::QuicHandshakeTimeout => {
            Some(base("client.quic.handshake_timeout", Confidence::Confirmed, SourceScope::ClientToPeer, Owner::Unknown, Severity::Error))
        }
        K::QuicIdleTimeout => {
            Some(base("client.quic.idle_timeout", Confidence::Confirmed, SourceScope::ClientToPeer, Owner::Unknown, Severity::Error))
        }
        K::QuicTransportError | K::QuicApplicationClosed | K::QuicOther => {
            let mut d =
                base("client.quic.connection_failed", Confidence::Unknown, SourceScope::ClientToPeer, Owner::Unknown, Severity::Error);
            if let Some(c) = f.quic_error_code {
                d = d.ev_at(E::NativeTransport, "quic.error_code", format!("0x{c:x}"), a.index);
            }
            Some(d)
        }
        K::DtlsHandshakeTimeout => {
            Some(base("client.dtls.handshake_timeout", Confidence::Confirmed, SourceScope::ClientToPeer, Owner::Unknown, Severity::Error))
        }
        K::DtlsHandshakeFailed => {
            Some(base("client.dtls.handshake_failed", Confidence::Unknown, SourceScope::ClientToPeer, Owner::Unknown, Severity::Error))
        }
        K::WsHandshakeRejected => None, // handled by the WebSocket rules
        _ => None,
    };
    if let Some(d) = d {
        out.push(d);
    }

    // ---- response started but did not complete ----
    if let Some(r) = ctx.input.response {
        let st = r.status.to_string();
        let mk = |code: &str, conf: Confidence, owner: Owner| {
            Draft::new(code, "transport.body", conf, SourceScope::ResponseDelivery, owner, Severity::Error)
                .ev_at(E::HttpStatus, "status", st.clone(), a.index)
                .ev_at(E::BodyCompletion, "body.completeness", format!("{:?}", r.body.completeness), a.index)
                .ev_at(E::BodyCompletion, "body.received_bytes", r.body.wire_bytes.to_string(), a.index)
                .ev_at(E::NativeTransport, "failure.kind", format!("{:?}", f.kind), a.index)
                .var("status", st.clone())
                .var("bytes", r.body.wire_bytes.to_string())
                .var("declared", r.body.declared_length.map(|d| d.to_string()).unwrap_or_else(|| "an unspecified number of".into()))
                .var("deadline_ms", f.deadline_ms.map(|d| d.to_string()).unwrap_or_else(|| "the configured".into()))
                .var("h2_code", f.h2_error_code.map(h2_name).unwrap_or_default())
                .var("host", host.clone())
        };
        match (r.body.completeness, f.kind) {
            (BodyCompleteness::Incomplete, K::BodyIdleTimeout) => {
                out.push(mk("response.body_idle_timeout", Confidence::Confirmed, Owner::Unknown))
            }
            (BodyCompleteness::Incomplete, K::H2StreamReset) => {
                out.push(mk("response.body_stream_reset", Confidence::Confirmed, Owner::Unknown))
            }
            (BodyCompleteness::Incomplete, K::TotalTimeout) => {
                out.push(mk("response.body_total_timeout", Confidence::Confirmed, Owner::Caller))
            }
            (BodyCompleteness::Incomplete, _) => out.push(mk("response.body_incomplete", Confidence::Confirmed, Owner::Unknown)),
            (BodyCompleteness::StoppedAtLocalLimit, _) => {
                out.push(mk("local.response_limit_reached", Confidence::Confirmed, Owner::Caller).var("limit", f.message.clone()))
            }
            (BodyCompleteness::Canceled, _) => out.push(mk("request.canceled_during_body", Confidence::Confirmed, Owner::Caller)),
            _ => {}
        }
    }
}

pub fn h2_name(code: u32) -> String {
    let n = match code {
        0 => "NO_ERROR",
        1 => "PROTOCOL_ERROR",
        2 => "INTERNAL_ERROR",
        3 => "FLOW_CONTROL_ERROR",
        4 => "SETTINGS_TIMEOUT",
        5 => "STREAM_CLOSED",
        6 => "FRAME_SIZE_ERROR",
        7 => "REFUSED_STREAM",
        8 => "CANCEL",
        9 => "COMPRESSION_ERROR",
        10 => "CONNECT_ERROR",
        11 => "ENHANCE_YOUR_CALM",
        12 => "INADEQUATE_SECURITY",
        13 => "HTTP_1_1_REQUIRED",
        _ => return format!("0x{code:x}"),
    };
    n.to_string()
}
