use super::Ctx;
use crate::{Draft, warn};
use anvil_domain::diagnostics::{Confidence, EvidenceSource as E, Owner, Severity, SourceScope};
use anvil_domain::execution::{Direction, FailureKind};
use anvil_domain::outcome::{ClosedBy, GrpcStatusSource, MasqueTunnel, OutcomeWarning, ProtocolStatus, WarningCode};

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
            (None, GrpcStatusSource::Missing)
                if http_status.is_some() => {
                    out.push(
                        Draft::new("app.grpc_status_missing", "protocol.grpc", Confidence::Confirmed, SourceScope::ResponseDelivery, Owner::Unknown, Severity::Error)
                            .ev_at(E::GrpcStatus, "grpc-status", "missing", idx)
                            .var("http_status", http_status.map(|s| s.to_string()).unwrap_or_default()),
                    );
                }
            _ => {}
        },
        ProtocolStatus::WebSocket { handshake_status, close_code, close_reason, closed_by } => {
            // Who started the closing handshake, stated from the evidence: a
            // 1000 that Anvil sent (user close, idle close) is not the peer's choice.
            let closer = match closed_by {
                ClosedBy::Peer => "The peer",
                ClosedBy::Client => "Anvil",
                ClosedBy::Timeout => "Anvil (a time limit elapsed)",
                ClosedBy::Abnormal | ClosedBy::NotClosed => "The session",
            };
            let base = |code: &str, conf: Confidence, owner: Owner, sev: Severity| {
                Draft::new(code, "protocol.websocket", conf, SourceScope::Unknown, owner, sev)
                    .ev_at(E::WebSocketClose, "close.code", close_code.map(|c| c.to_string()).unwrap_or_else(|| "none".into()), idx)
                    .ev_at(E::WebSocketClose, "close.reason", close_reason.clone(), idx)
                    .ev_at(E::WebSocketClose, "closed_by", format!("{closed_by:?}"), idx)
                    .var("code", close_code.map(|c| c.to_string()).unwrap_or_else(|| "none".into()))
                    .var("reason", close_reason.clone())
                    .var("closer", closer.to_string())
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
        ProtocolStatus::Udp { datagrams_sent, datagrams_received, window_ms, masque } => {
            if let Some(m) = masque {
                masque_rules(ctx, m, out);
            }
            // A DTLS peer that completed the handshake and then sent
            // close_notify without answering did answer: it closed the
            // session. "Nothing is listening" is then contradicted, so the
            // generic silent-UDP finding would mislead.
            let peer_closed = ctx
                .input
                .stream
                .map(|s| s.messages.iter().any(|m| m.direction == Direction::Received && m.kind == "close_notify"))
                .unwrap_or(false);
            if *datagrams_received == 0 && *datagrams_sent > 0 && peer_closed {
                out.push(
                    Draft::new(
                        "dtls.closed_without_response",
                        "protocol.streams",
                        Confidence::Confirmed,
                        SourceScope::ClientToPeer,
                        Owner::Unknown,
                        Severity::Error,
                    )
                    .ev(E::NativeTransport, "dtls.close_notify", "received")
                    .ev(E::NativeTransport, "udp.sent", datagrams_sent.to_string())
                    .ev(E::NativeTransport, "udp.received", "0")
                    .var("sent", datagrams_sent.to_string())
                    .var("host", ctx.target_host()),
                );
            } else if *datagrams_received == 0 && *datagrams_sent > 0 {
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
        ProtocolStatus::Tcp { bytes_sent, bytes_received, half_closed, closed_by } => {
            if *half_closed && *bytes_received > 0 {
                out.push(
                    Draft::new("tcp.reply_after_half_close", "protocol.streams", Confidence::Confirmed, SourceScope::ClientToPeer, Owner::Unknown, Severity::Info)
                        .var("bytes", bytes_received.to_string()),
                );
            }
            let ended_by_peer = matches!(closed_by, ClosedBy::Peer | ClosedBy::Abnormal);
            if ended_by_peer && *bytes_received == 0 {
                // The connection itself was established; the peer (or a layer-4
                // proxy such as a gateway stream listener) ended it before any
                // data came back. L4 carries no in-band reason.
                let how = if *closed_by == ClosedBy::Abnormal {
                    "reset the connection (or it ended with an error)"
                } else {
                    "closed the connection (FIN)"
                };
                out.push(
                    Draft::new("tcp.closed_without_data", "protocol.streams", Confidence::Confirmed, SourceScope::ClientToPeer, Owner::Unknown, Severity::Warning)
                        .ev_at(E::NativeTransport, "tcp.bytes_sent", bytes_sent.to_string(), idx)
                        .ev_at(E::NativeTransport, "tcp.bytes_received", "0", idx)
                        .ev_at(E::NativeTransport, "closed_by", format!("{closed_by:?}"), idx)
                        .var("host", ctx.target_host())
                        .var("sent", bytes_sent.to_string())
                        .var("how", how.to_string()),
                );
            } else if *closed_by == ClosedBy::Abnormal {
                out.push(
                    Draft::new("tcp.closed_abnormally", "protocol.streams", Confidence::Confirmed, SourceScope::ClientToPeer, Owner::Unknown, Severity::Error)
                        .ev_at(E::NativeTransport, "tcp.bytes_received", bytes_received.to_string(), idx)
                        .var("host", ctx.target_host())
                        .var("bytes", bytes_received.to_string()),
                );
            }
        }
        _ => {}
    }
}

/// RFC 9298 CONNECT-UDP tunnel facts. Every claim is about the MASQUE proxy
/// Anvil talked to; a refusal or a missing capability is never a claim
/// about the UDP target, which the proxy may not have contacted at all.
fn masque_rules(ctx: &Ctx<'_>, m: &MasqueTunnel, out: &mut Vec<Draft>) {
    let idx = ctx.attempt_index();
    let failure = ctx.final_attempt().and_then(|a| a.failure.as_ref());
    let base = |code: &str, conf: Confidence, owner: Owner, sev: Severity| {
        Draft::new(code, "protocol.masque", conf, SourceScope::ForwardProxy, owner, sev)
            .ev_at(E::NativeTransport, "masque.proxy", m.proxy.clone(), idx)
            .ev_at(E::NativeTransport, "masque.target", m.target.clone(), idx)
            .var("proxy", m.proxy.clone())
            .var("target", m.target.clone())
    };
    let settings = |d: Draft| {
        let flag = |v: Option<bool>| v.map(|b| if b { "enabled" } else { "not enabled" }).unwrap_or("not received").to_string();
        d.ev_at(E::NativeTransport, "h3.settings.enable_connect_protocol", flag(m.extended_connect), idx).ev_at(
            E::NativeTransport,
            "h3.settings.h3_datagram",
            flag(m.h3_datagrams),
            idx,
        )
    };
    if let Some(s) = m.connect_status.filter(|s| !(200..300).contains(s)) {
        let mut d = base("masque.proxy_refused", Confidence::Confirmed, Owner::Unknown, Severity::Error)
            .ev_at(E::HttpStatus, "connect.status", s.to_string(), idx)
            .var("status", s.to_string());
        if let Some(r) = ctx.input.response {
            for v in r.header_values("proxy-status") {
                d = d.ev_at(E::HttpHeader, "header.proxy-status", v.to_string(), idx);
            }
        }
        if let Some(e) = &ctx.body.json_error {
            d = d.ev_at(E::BodyContent, "body.error", e.clone(), idx);
        }
        out.push(d);
    }
    if failure.map(|f| f.kind == FailureKind::MasqueUnsupported).unwrap_or(false) {
        let d = match (m.extended_connect, m.h3_datagrams) {
            (None, _) => base("masque.settings_not_received", Confidence::Unknown, Owner::Unknown, Severity::Error),
            (Some(false), _) => base("masque.extended_connect_unavailable", Confidence::Confirmed, Owner::Unknown, Severity::Error),
            (Some(true), _) => base("masque.no_datagram_support", Confidence::Confirmed, Owner::Unknown, Severity::Error),
        };
        out.push(settings(d));
    }
    if m.connect_status.map(|s| (200..300).contains(&s)).unwrap_or(false) && m.closed_by == ClosedBy::Abnormal {
        let mut d = base("masque.tunnel_ended_abnormally", Confidence::Confirmed, Owner::Unknown, Severity::Error).ev_at(
            E::NativeTransport,
            "closed_by",
            format!("{:?}", m.closed_by),
            idx,
        );
        if let Some(f) = failure {
            d = d.ev_at(E::NativeTransport, "failure.kind", format!("{:?}", f.kind), idx);
            if let Some(c) = f.quic_error_code {
                d = d.ev_at(E::NativeTransport, "h3.error_code", format!("0x{c:x}"), idx);
            }
        }
        out.push(d);
    }
}

#[cfg(test)]
mod tests {
    use crate::facts::{DiagnosticInput, FerrumTrust};
    use anvil_domain::diagnostics::DiagnosticFinding;
    use anvil_domain::outcome::{ClosedBy, ProtocolStatus};
    use anvil_domain::request::Protocol;

    fn diagnose(protocol: Protocol, status: ProtocolStatus) -> Vec<DiagnosticFinding> {
        let trust = FerrumTrust::NotConfigured;
        let input = DiagnosticInput {
            protocol,
            method: "GET",
            preparation_failure: None,
            attempts: &[],
            response: None,
            body: &[],
            stream: None,
            protocol_status: &status,
            trust: &trust,
            tls_verification_enabled: true,
            credentials_stripped_on_redirect: false,
            protocol_fallback_from: None,
        };
        crate::diagnose(&input).findings
    }

    fn ws(code: u16, by: ClosedBy) -> ProtocolStatus {
        ProtocolStatus::WebSocket { handshake_status: Some(101), close_code: Some(code), close_reason: String::new(), closed_by: by }
    }

    fn find<'a>(f: &'a [DiagnosticFinding], code: &str) -> &'a DiagnosticFinding {
        f.iter().find(|x| x.code == code).unwrap_or_else(|| panic!("missing {code}: {:?}", f.iter().map(|x| &x.code).collect::<Vec<_>>()))
    }

    #[test]
    fn a_normal_close_names_who_closed() {
        let peer = diagnose(Protocol::WebSocket, ws(1000, ClosedBy::Peer));
        let e = &find(&peer, "ws.closed_normally").explanation;
        assert!(e.starts_with("The peer closed"), "{e}");
        // Anvil's own close (user close or automation idle close) is not the peer's choice.
        let client = diagnose(Protocol::WebSocket, ws(1000, ClosedBy::Client));
        let e = &find(&client, "ws.closed_normally").explanation;
        assert!(e.starts_with("Anvil closed"), "{e}");
        assert!(!e.to_lowercase().contains("peer"), "{e}");
    }

    #[test]
    fn a_peer_close_leaves_open_which_hop_authored_it() {
        // Ferrum 0.9.5 answers a backend's silent TCP drop with its own Close 1002.
        let f = diagnose(Protocol::WebSocket, ws(1002, ClosedBy::Peer));
        let d = find(&f, "ws.closed_other");
        assert!(d.does_not_prove.iter().any(|x| x.contains("Which hop")), "{:?}", d.does_not_prove);
        assert!(d.alternatives.iter().any(|x| x.contains("gateway or proxy")), "{:?}", d.alternatives);
    }

    #[test]
    fn a_scripted_policy_close_is_not_attributed_to_the_peer() {
        let f = diagnose(Protocol::WebSocket, ws(1008, ClosedBy::Client));
        assert!(!find(&f, "ws.closed_policy").explanation.to_lowercase().contains("the peer"));
    }

    fn tcp(sent: u64, received: u64, by: ClosedBy) -> ProtocolStatus {
        ProtocolStatus::Tcp { bytes_sent: sent, bytes_received: received, half_closed: false, closed_by: by }
    }

    #[test]
    fn a_tcp_close_without_any_data_is_explained_without_blaming_the_client_leg() {
        for by in [ClosedBy::Peer, ClosedBy::Abnormal] {
            let f = diagnose(Protocol::Tcp, tcp(6, 0, by));
            let d = find(&f, "tcp.closed_without_data");
            assert!(d.does_not_prove.iter().any(|x| x.contains("setup completed")), "{:?}", d.does_not_prove);
            assert!(d.alternatives.iter().any(|x| x.contains("its own upstream")), "{:?}", d.alternatives);
            assert!(!f.iter().any(|x| x.code.starts_with("client.")), "no client-leg failure is claimed");
            assert!(!f.iter().any(|x| x.code == "tcp.closed_abnormally"), "one finding per session end");
        }
    }

    #[test]
    fn a_reset_after_data_stays_an_abnormal_end_and_ordinary_ends_are_silent() {
        let f = diagnose(Protocol::Tcp, tcp(6, 12, ClosedBy::Abnormal));
        assert!(find(&f, "tcp.closed_abnormally").explanation.contains("12"));
        assert!(!f.iter().any(|x| x.code == "tcp.closed_without_data"));
        // Anvil stopping by itself (expected frames, idle limit) is not a peer close.
        for by in [ClosedBy::Client, ClosedBy::Timeout] {
            assert!(diagnose(Protocol::Tcp, tcp(6, 0, by)).iter().all(|x| !x.code.starts_with("tcp.closed")));
        }
        // A peer that answered and then closed is an ordinary end.
        assert!(diagnose(Protocol::Tcp, tcp(6, 6, ClosedBy::Peer)).iter().all(|x| !x.code.starts_with("tcp.closed")));
    }
}
