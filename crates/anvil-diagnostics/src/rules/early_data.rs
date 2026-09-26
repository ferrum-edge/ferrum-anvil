//! TLS 1.3 / QUIC 0-RTT early data (RFC 8446 §2.3, RFC 9001 §4.6) and the
//! `425 Too Early` status (RFC 8470).
//!
//! Every claim here comes from the attempt's own early-data evidence (what
//! the handshake reported) or from an observed status code. A `425` says the
//! answering server declined to process the request; it never says which
//! component behind the address answered (a gateway's early-data policy or a
//! backend that saw `Early-Data: 1`), so that finding keeps an unknown scope.

use super::Ctx;
use crate::Draft;
use anvil_domain::diagnostics::{Confidence, EvidenceSource as E, Owner, Severity, SourceScope};
use anvil_domain::execution::{AttemptObservation, AttemptReason, EarlyDataNotUsed, EarlyDataObservation, EarlyDataTransport};

fn flag(b: bool) -> &'static str {
    if b { "true" } else { "false" }
}

fn transport(ed: &EarlyDataObservation) -> &'static str {
    match ed.transport {
        EarlyDataTransport::Quic => "QUIC 0-RTT",
        EarlyDataTransport::Tls => "TLS 1.3 early data",
    }
}

fn not_used_text(r: EarlyDataNotUsed) -> &'static str {
    match r {
        EarlyDataNotUsed::NoTicket => "there was no session ticket from an earlier connection to this server",
        EarlyDataNotUsed::TicketWithoutEarlyData => "the server's session ticket did not allow early data",
        EarlyDataNotUsed::MethodNotEligible => "the method is not eligible for early data under this request's policy",
        EarlyDataNotUsed::ConnectionReused => "an established connection carried it",
        EarlyDataNotUsed::RetryAfterTooEarly => "it was the retry after 425 Too Early",
        EarlyDataNotUsed::AlpnNotFixed => "the HTTP version policy offers more than one protocol over TCP",
        EarlyDataNotUsed::ThroughProxy => "a proxy or tunnel carried the connection",
        EarlyDataNotUsed::HandshakeCompletedFirst => "the handshake completed before the request was written",
    }
}

fn early_evidence(d: Draft, ed: &EarlyDataObservation, idx: u32) -> Draft {
    let mut d = d
        .ev_at(E::NativeTransport, "early_data.transport", transport(ed), idx)
        .ev_at(E::NativeTransport, "early_data.offered", flag(ed.offered), idx)
        .ev_at(E::NativeTransport, "early_data.resumption_attempted", flag(ed.resumption_attempted), idx);
    if let Some(a) = ed.accepted {
        d = d.ev_at(E::NativeTransport, "early_data.accepted", flag(a), idx);
    }
    if let Some(r) = ed.resumption_accepted {
        d = d.ev_at(E::NativeTransport, "early_data.resumption_accepted", flag(r), idx);
    }
    if ed.bytes > 0 {
        d = d.ev_at(
            E::NativeTransport,
            "early_data.bytes",
            format!("{}{}", ed.bytes, if ed.bytes_estimated { " (estimated)" } else { "" }),
            idx,
        );
    }
    if ed.resent_after_handshake {
        d = d.ev_at(E::NativeTransport, "early_data.resent_after_handshake", "true", idx);
    }
    if let Some(r) = ed.not_used {
        d = d.ev_at(E::NativeTransport, "early_data.not_used", format!("{r:?}"), idx);
    }
    d
}

pub fn rules(ctx: &Ctx<'_>, out: &mut Vec<Draft>) {
    let attempts = ctx.input.attempts;
    let host = ctx.target_host();
    too_early(ctx, attempts, &host, out);

    if let Some(a) = attempts.iter().find(|a| a.early_data.as_ref().is_some_and(|e| e.offered && e.accepted == Some(true))) {
        let ed = a.early_data.as_ref().expect("checked");
        let d = Draft::new(
            "early_data.accepted",
            "protocol.early_data",
            Confidence::Confirmed,
            SourceScope::ClientToPeer,
            Owner::Caller,
            Severity::Info,
        )
        .var("method", a.method.clone())
        .var("host", host.clone())
        .var("transport", transport(ed))
        .var("bytes", ed.bytes.to_string());
        out.push(early_evidence(d, ed, a.index));
    }

    if let Some(a) = attempts.iter().find(|a| a.early_data.as_ref().is_some_and(|e| e.offered && e.accepted == Some(false))) {
        let ed = a.early_data.as_ref().expect("checked");
        let resend = if ed.resent_after_handshake {
            "Anvil sent the same request again once the handshake had completed"
        } else {
            "The request was not sent again, because the attempt ended first"
        };
        let d = Draft::new(
            "early_data.rejected",
            "protocol.early_data",
            Confidence::Confirmed,
            SourceScope::ClientToPeer,
            Owner::Caller,
            Severity::Info,
        )
        .var("host", host.clone())
        .var("transport", transport(ed))
        .var("bytes", ed.bytes.to_string())
        .var("resend", resend);
        out.push(early_evidence(d, ed, a.index));
    }

    // A full handshake under the opt-in that delivered no ticket: the next
    // request cannot resume. Only when the exchange completed on a new connection.
    if let Some(a) = attempts.iter().find(|a| {
        a.response_status.is_some()
            && a.connection.as_ref().is_some_and(|c| !c.reused)
            && a.early_data
                .as_ref()
                .is_some_and(|e| e.not_used == Some(EarlyDataNotUsed::NoTicket) && !e.resumption_attempted && e.tickets_received == 0)
    }) {
        let ed = a.early_data.as_ref().expect("checked");
        let d = Draft::new(
            "early_data.no_ticket",
            "protocol.early_data",
            Confidence::Confirmed,
            SourceScope::ClientToPeer,
            Owner::Caller,
            Severity::Info,
        )
        .var("host", host.clone())
        .var("transport", transport(ed));
        out.push(early_evidence(d, ed, a.index).ev_at(E::NativeTransport, "early_data.tickets_received", "0", a.index));
    }

    if let Some(a) =
        attempts.iter().find(|a| a.early_data.as_ref().is_some_and(|e| e.not_used == Some(EarlyDataNotUsed::TicketWithoutEarlyData)))
    {
        let ed = a.early_data.as_ref().expect("checked");
        let d = Draft::new(
            "early_data.ticket_without_early_data",
            "protocol.early_data",
            Confidence::Confirmed,
            SourceScope::ClientToPeer,
            Owner::Caller,
            Severity::Info,
        )
        .var("host", host.clone())
        .var("transport", transport(ed));
        out.push(early_evidence(d, ed, a.index));
    }
}

/// `425 Too Early` on any attempt: what was sent, and the retry outcome.
fn too_early(ctx: &Ctx<'_>, attempts: &[AttemptObservation], host: &str, out: &mut Vec<Draft>) {
    let Some((pos, a)) = attempts.iter().enumerate().find(|(_, a)| a.response_status == Some(425)) else { return };
    let idx = a.index;
    let sent_early = a.early_data.as_ref().is_some_and(|e| e.offered && e.accepted == Some(true));
    let sent = match &a.early_data {
        Some(e) if e.offered && e.accepted == Some(true) => {
            format!("Anvil sent this request as {} and the server accepted the early data", transport(e))
        }
        Some(e) if e.offered => {
            format!(
                "Anvil offered this request as {}, the server rejected the early data, and the request was sent again after the handshake",
                transport(e)
            )
        }
        Some(e) => format!(
            "Anvil did not send this request as early data ({})",
            e.not_used.map(not_used_text).unwrap_or("it was sent after the handshake")
        ),
        None => "Anvil did not send this request as early data (early data is off for this request)".to_string(),
    };
    let retry = attempts[pos + 1..].iter().find(|r| r.reason == AttemptReason::TooEarlyRetry);
    let retry_text = match retry {
        Some(r) => {
            let outcome = match (r.response_status, &r.failure) {
                (Some(s), _) => format!("HTTP {s}"),
                (None, Some(f)) => format!("no response ({:?})", f.kind),
                (None, None) => "no response".to_string(),
            };
            format!("Anvil sent it once more after the handshake had completed, not as early data (attempt {}): {outcome}.", r.index)
        }
        None => match &a.early_data {
            None => {
                "It was not retried automatically: Anvil retries after 425 only for requests covered by the early-data opt-in.".to_string()
            }
            Some(e) if !e.method_eligible => "It was not retried automatically: its method is not eligible for early data.".to_string(),
            Some(_) if a.reason == AttemptReason::TooEarlyRetry => {
                "It was not retried again: Anvil retries after 425 at most once.".to_string()
            }
            Some(_) => "It was not retried automatically.".to_string(),
        },
    };
    let final_ok = ctx.input.response.map(|r| r.status < 400).unwrap_or(false);
    let severity = if final_ok { Severity::Info } else { Severity::Warning };
    let mut d =
        Draft::new("request.too_early", "protocol.early_data", Confidence::Confirmed, SourceScope::Unknown, Owner::Caller, severity)
            .ev_at(E::HttpStatus, "status", "425", idx)
            .var("method", a.method.clone())
            .var("host", host.to_string())
            .var("sent", sent)
            .var("retry", retry_text);
    if let Some(e) = &a.early_data {
        d = early_evidence(d, e, idx);
    }
    if let Some(r) = retry {
        d = d.ev_at(E::NativeTransport, "retry.attempt", r.index.to_string(), r.index);
        if let Some(s) = r.response_status {
            d = d.ev_at(E::HttpStatus, "retry.status", s.to_string(), r.index);
        }
    }
    if ctx.body.json_error.is_some() && attempts.last().map(|l| l.response_status == Some(425)).unwrap_or(false) {
        d = d.ev_at(E::BodyContent, "body.error", ctx.body.json_error.clone().unwrap_or_default(), idx);
    }
    if !sent_early {
        d = d
            .not_proven("That the request travelled as early data: Anvil did not send it as accepted early data.")
            .alt("The server counts a request that arrives right after its handshake completes as early data (a race some servers resolve in favour of refusing).")
            .alt("An `Early-Data: 1` header on the request (set in the request's headers, or added by an intermediary) made the server treat it as forwarded early data (RFC 8470 §5.1).")
            .alt("A component behind the server answered 425 for its own reasons.");
    }
    out.push(d);
}
