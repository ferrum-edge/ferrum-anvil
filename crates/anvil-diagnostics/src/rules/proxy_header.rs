//! PROXY protocol evidence on stream sessions and HTTP-family connections.
//!
//! A listener that requires PROXY protocol (Ferrum Edge
//! `stream_proxy_protocol: true`, HAProxy `accept-proxy`, nginx `listen …
//! proxy_protocol`) closes a TCP connection immediately — no data, no reason
//! — when the header is missing, malformed or comes from an untrusted peer,
//! and silently drops datagrams whose envelope fails. A listener that does
//! not expect a header reads it as the start of the request or of the TLS
//! handshake and rejects that instead. None of these public outcomes is ever
//! enough to claim the cause:
//!
//! * no header was sent and the peer closed without data: the existing close
//!   finding gains "the listener may require PROXY protocol" as one more
//!   alternative (no claim, no confidence of its own);
//! * a header was sent and the peer closed without data:
//!   `tcp.proxy_header_maybe_rejected`, `unknown` — or `likely` when Anvil's
//!   own check of the bytes it sent found them malformed;
//! * a header was sent on an HTTP-family connection and the peer answered
//!   400, a TLS alert or a close before any response: the public finding
//!   gains "the listener may not expect a PROXY header" as an alternative
//!   (next to `tcp.proxy_header_maybe_rejected` for the close);
//! * an envelope was sent and nothing came back: the no-response finding
//!   gains "the listener may have dropped the envelope" as an alternative.
//!
//! For HTTP-family requests only a **new** connection is considered: a
//! reused connection had already carried requests, so its header (or its
//! absence) was accepted.

use super::Ctx;
use crate::Draft;
use anvil_domain::diagnostics::{Confidence, EvidenceSource as E, Owner, Severity, SourceScope};
use anvil_domain::execution::{FailureKind as K, Phase};
use anvil_domain::outcome::{ClosedBy, ProtocolStatus};
use anvil_domain::proxy_protocol::{ProxyHeaderFormat, ProxyHeaderObservation};
use anvil_domain::request::Protocol;

const HEADER_MAY_BE_REQUIRED: &str = "alt.proxy_protocol.header_may_be_required";
const HEADER_MAY_BE_UNEXPECTED: &str = "alt.proxy_protocol.header_may_be_unexpected";
const ENVELOPE_MAY_BE_DROPPED: &str = "alt.proxy_protocol.envelope_may_be_dropped";

/// Close findings that "the listener may require a header" can explain.
const CLOSE_FINDINGS: &[&str] =
    &["tcp.closed_without_data", "client.tls.connection_closed", "exchange.closed_before_response", "exchange.reset_before_response"];

/// Public refusals of a listener that read a PROXY header as the start of
/// the request (HTTP 400) or of the TLS handshake (an alert).
const REFUSAL_FINDINGS: &[&str] = &[
    "http.client_error",
    "ws.handshake_rejected",
    "app.grpc_status_missing",
    "client.tls.peer_alert",
    "client.tls.version_mismatch",
    "client.tls.not_tls",
    "client.tls.other",
];

fn http_family(p: Protocol) -> bool {
    matches!(p, Protocol::Http | Protocol::WebSocket | Protocol::Grpc | Protocol::Sse)
}

fn sent_header<'a>(ctx: &Ctx<'a>) -> Option<&'a ProxyHeaderObservation> {
    ctx.final_attempt().and_then(|a| a.connection.as_ref()).and_then(|c| c.proxy_header.as_ref())
}

/// The final attempt ran on a connection it opened itself (so a header, or
/// its absence, was the first thing this listener read from it).
fn fresh_connection(ctx: &Ctx<'_>) -> bool {
    ctx.final_attempt().and_then(|a| a.connection.as_ref()).map(|c| !c.reused && c.prior_requests == 0).unwrap_or(false)
}

/// How the peer ended a TCP/TLS connection without sending data, if it did.
fn closed_without_data(ctx: &Ctx<'_>) -> Option<&'static str> {
    if let ProtocolStatus::Tcp { bytes_received: 0, closed_by, .. } = ctx.input.protocol_status {
        return match closed_by {
            ClosedBy::Peer => Some("closed the connection (FIN)"),
            ClosedBy::Abnormal => Some("reset the connection (or it ended with an error)"),
            _ => None,
        };
    }
    let http = http_family(ctx.input.protocol) && ctx.input.response.is_none();
    match ctx.final_failure().map(|f| f.kind) {
        Some(K::TlsPeerClosed | K::TlsReset) => Some("closed or reset the connection during the TLS handshake"),
        Some(K::ClosedBeforeResponse) if http => Some("closed the connection before any response"),
        Some(K::ResetBeforeResponse) if http => Some("reset the connection before any response"),
        _ => None,
    }
}

/// The peer answered HTTP 400 on the final attempt.
fn bad_request(ctx: &Ctx<'_>) -> bool {
    ctx.input.response.map(|r| r.status == 400).unwrap_or(false)
}

pub fn rules(ctx: &Ctx<'_>, out: &mut Vec<Draft>) {
    let protocol = ctx.input.protocol;
    if protocol != Protocol::Tcp && !(http_family(protocol) && fresh_connection(ctx)) {
        return;
    }
    let Some(h) = sent_header(ctx) else { return };
    if h.format == ProxyHeaderFormat::V2Datagram {
        return;
    }
    let Some(how) = closed_without_data(ctx) else { return };
    let idx = ctx.attempt_index();
    let malformed = !h.well_formed;
    let (confidence, owner) = if malformed { (Confidence::Likely, Owner::Caller) } else { (Confidence::Unknown, Owner::Unknown) };
    let format = match h.format {
        ProxyHeaderFormat::V1 => "PROXY v1",
        ProxyHeaderFormat::V2 => "PROXY v2",
        ProxyHeaderFormat::Raw => "custom (raw) PROXY",
        ProxyHeaderFormat::V2Datagram => "PROXY v2 DGRAM",
    };
    let mut d = Draft::new(
        "tcp.proxy_header_maybe_rejected",
        "protocol.proxy_header",
        confidence,
        SourceScope::ClientToPeer,
        owner,
        Severity::Warning,
    )
    .ev_at(E::NativeTransport, "proxy_header.format", format, idx)
    .ev_at(E::NativeTransport, "proxy_header.length", h.length.to_string(), idx)
    .ev_at(E::NativeTransport, "proxy_header.family", h.family.clone(), idx)
    .ev_at(E::LocalValidation, "proxy_header.well_formed", h.well_formed.to_string(), idx)
    .ev_at(E::NativeTransport, "peer.ended", how, idx)
    .var("host", ctx.target_host())
    .var("format", format)
    .var("length", h.length.to_string())
    .var("how", how)
    .var(
        "malformed",
        match (&h.problem, malformed) {
            (Some(p), true) => format!("Anvil's own check of the bytes it sent found them malformed: {p}."),
            _ => String::new(),
        },
    );
    if let Some(p) = &h.problem {
        d = d.ev_at(E::LocalValidation, "proxy_header.problem", p.clone(), idx);
    }
    out.push(d);
}

/// Attach PROXY-protocol alternatives to the close / silence / refusal
/// findings other rules produced. Runs after every other rule.
pub fn annotate(ctx: &Ctx<'_>, drafts: &mut [Draft]) {
    let header = sent_header(ctx);
    match ctx.input.protocol {
        Protocol::Tcp if header.is_none() => {
            for d in drafts.iter_mut().filter(|d| matches!(d.code.as_str(), "tcp.closed_without_data" | "client.tls.connection_closed")) {
                d.alt_fragments.push(HEADER_MAY_BE_REQUIRED);
            }
        }
        p if http_family(p) && fresh_connection(ctx) => match header {
            None if closed_without_data(ctx).is_some() => {
                for d in drafts.iter_mut().filter(|d| CLOSE_FINDINGS.contains(&d.code.as_str())) {
                    d.alt_fragments.push(HEADER_MAY_BE_REQUIRED);
                }
            }
            Some(h) if h.format != ProxyHeaderFormat::V2Datagram => {
                let tls_alert = ctx.final_failure().map(|f| f.phase == Phase::TlsHandshake && f.tls_alert.is_some()).unwrap_or(false);
                let refused = bad_request(ctx) || tls_alert;
                let closed = closed_without_data(ctx).is_some();
                for d in drafts.iter_mut().filter(|d| {
                    (refused && REFUSAL_FINDINGS.contains(&d.code.as_str())) || (closed && CLOSE_FINDINGS.contains(&d.code.as_str()))
                }) {
                    d.alt_fragments.push(HEADER_MAY_BE_UNEXPECTED);
                }
            }
            _ => {}
        },
        Protocol::Udp if header.is_some_and(|h| h.format == ProxyHeaderFormat::V2Datagram) => {
            for d in drafts.iter_mut().filter(|d| matches!(d.code.as_str(), "udp.no_response" | "client.dtls.handshake_timeout")) {
                d.alt_fragments.push(ENVELOPE_MAY_BE_DROPPED);
            }
        }
        _ => {}
    }
}

#[cfg(test)]
mod tests {
    use crate::facts::{DiagnosticInput, FerrumTrust};
    use anvil_domain::diagnostics::{Confidence, DiagnosticFinding};
    use anvil_domain::execution::*;
    use anvil_domain::outcome::{ClosedBy, ProtocolStatus};
    use anvil_domain::proxy_protocol::{ProxyHeaderFormat, ProxyHeaderObservation};
    use anvil_domain::request::Protocol;

    fn header(format: ProxyHeaderFormat, well_formed: bool) -> ProxyHeaderObservation {
        ProxyHeaderObservation {
            format,
            command: None,
            family: "AF_INET".into(),
            source: Some("203.0.113.7:4242".into()),
            source_origin: None,
            destination: Some("127.0.0.1:18901".into()),
            destination_origin: None,
            length: 28,
            hex: "00".into(),
            text: None,
            tlvs: vec![],
            well_formed,
            problem: if well_formed { None } else { Some("invalid PROXY v2 signature".into()) },
            authenticated: false,
            listener_binding: None,
            sender_id: None,
            epoch: None,
            first_sequence: None,
            last_sequence: None,
            datagrams: 1,
        }
    }

    fn attempt(h: Option<ProxyHeaderObservation>, failure: Option<TransportFailure>) -> AttemptObservation {
        let mut c = ConnectionObservation {
            id: 1,
            reused: false,
            protocol: Some("tcp".into()),
            local_address: None,
            remote_address: None,
            resolved_addresses: vec![],
            resolution_source: None,
            connect_attempts: vec![],
            via_proxy: None,
            tls: None,
            tunnel: None,
            prior_requests: 0,
            proxy_header: None,
        };
        c.proxy_header = h;
        AttemptObservation {
            index: 0,
            reason: AttemptReason::Initial,
            method: "TCP".into(),
            url: "tcp://127.0.0.1:18901".into(),
            started_at: chrono::Utc::now(),
            connection: Some(c),
            phases: vec![],
            dispatch: DispatchState::Sent,
            bytes: ByteCounts::default(),
            response_status: None,
            failure,
            duration_us: 0,
        }
    }

    fn diagnose(protocol: Protocol, a: AttemptObservation, status: ProtocolStatus) -> Vec<DiagnosticFinding> {
        diagnose_with(protocol, a, status, None)
    }

    fn diagnose_with(
        protocol: Protocol,
        a: AttemptObservation,
        status: ProtocolStatus,
        response: Option<&ResponseRecord>,
    ) -> Vec<DiagnosticFinding> {
        let trust = FerrumTrust::NotConfigured;
        let attempts = [a];
        let input = DiagnosticInput {
            protocol,
            method: "TCP",
            preparation_failure: None,
            attempts: &attempts,
            response,
            body: &[],
            stream: None,
            protocol_status: &status,
            trust: &trust,
            tls_verification_enabled: true,
            credentials_stripped_on_redirect: false,
            protocol_fallback_from: None,
            workload: None,
        };
        crate::diagnose(&input).findings
    }

    fn tcp(received: u64, by: ClosedBy) -> ProtocolStatus {
        ProtocolStatus::Tcp { bytes_sent: 6, bytes_received: received, half_closed: false, closed_by: by }
    }

    fn find<'a>(f: &'a [DiagnosticFinding], code: &str) -> Option<&'a DiagnosticFinding> {
        f.iter().find(|x| x.code == code)
    }

    const MAY_REQUIRE: &str = "may require a PROXY protocol header";
    const MAY_NOT_EXPECT: &str = "may not expect a PROXY protocol header";

    fn reused(mut a: AttemptObservation) -> AttemptObservation {
        if let Some(c) = a.connection.as_mut() {
            c.reused = true;
            c.prior_requests = 1;
        }
        a
    }

    fn response(status: u16) -> ResponseRecord {
        ResponseRecord {
            status,
            reason: None,
            http_version: "HTTP/1.1".into(),
            headers: vec![],
            trailers: vec![],
            trailers_received: false,
            body: BodyCapture {
                completeness: BodyCompleteness::Complete,
                wire_bytes: 0,
                declared_length: Some(0),
                captured_bytes: 0,
                display_truncated: false,
                content_type: None,
                content_encoding: None,
                decoded_bytes: None,
                blob_sha256: None,
            },
        }
    }

    #[test]
    fn fragments_are_worded_in_the_catalog() {
        let c = crate::render::catalog();
        for k in [super::HEADER_MAY_BE_REQUIRED, super::HEADER_MAY_BE_UNEXPECTED, super::ENVELOPE_MAY_BE_DROPPED] {
            assert!(c.fragments.get(k).is_some_and(|t| !t.trim().is_empty()), "{k}");
        }
    }

    #[test]
    fn a_bare_close_without_a_header_only_adds_an_alternative() {
        let f = diagnose(Protocol::Tcp, attempt(None, None), tcp(0, ClosedBy::Peer));
        let d = find(&f, "tcp.closed_without_data").expect("close finding");
        assert!(d.alternatives.iter().any(|a| a.contains(MAY_REQUIRE)), "{:?}", d.alternatives);
        assert!(find(&f, "tcp.proxy_header_maybe_rejected").is_none());
        assert!(
            f.iter().all(|x| !(x.confidence == Confidence::Confirmed && x.explanation.contains("PROXY"))),
            "no confirmed PROXY claim from a bare close"
        );
        // An ordinary end (the peer answered) gets nothing.
        let ok = diagnose(Protocol::Tcp, attempt(None, None), tcp(12, ClosedBy::Peer));
        assert!(ok.iter().all(|x| x.alternatives.iter().all(|a| !a.contains(MAY_REQUIRE))));
    }

    #[test]
    fn a_close_on_a_new_connection_without_a_header_gets_the_alternative_on_tcp_and_http_family() {
        let fail = TransportFailure::new(Phase::TlsHandshake, FailureKind::TlsPeerClosed, "eof");
        let f = diagnose(Protocol::Tcp, attempt(None, Some(fail.clone())), ProtocolStatus::None);
        let d = find(&f, "client.tls.connection_closed").expect("tls close");
        assert!(d.alternatives.iter().any(|a| a.contains(MAY_REQUIRE)));
        assert_eq!(d.confidence, Confidence::Unknown);
        for p in [Protocol::Http, Protocol::WebSocket, Protocol::Grpc, Protocol::Sse] {
            let http = diagnose(p, attempt(None, Some(fail.clone())), ProtocolStatus::None);
            let d = find(&http, "client.tls.connection_closed").unwrap();
            assert!(d.alternatives.iter().any(|a| a.contains(MAY_REQUIRE)), "{p:?}");
            assert_eq!(d.confidence, Confidence::Unknown, "an alternative never raises confidence");
        }
        // An HTTP connection closed before the response, after the request was written.
        let closed = TransportFailure::new(Phase::AwaitResponseHeaders, FailureKind::ClosedBeforeResponse, "closed");
        let f = diagnose(Protocol::Http, attempt(None, Some(closed.clone())), ProtocolStatus::None);
        assert!(find(&f, "exchange.closed_before_response").unwrap().alternatives.iter().any(|a| a.contains(MAY_REQUIRE)));
        // A reused connection had already been accepted: nothing to add.
        let f = diagnose(Protocol::Http, reused(attempt(None, Some(closed))), ProtocolStatus::None);
        assert!(find(&f, "exchange.closed_before_response").unwrap().alternatives.iter().all(|a| !a.contains(MAY_REQUIRE)));
        let f = diagnose(Protocol::Udp, attempt(None, Some(fail)), ProtocolStatus::None);
        assert!(f.iter().all(|x| x.alternatives.iter().all(|a| !a.contains(MAY_REQUIRE))));
    }

    #[test]
    fn http_family_header_then_a_close_is_maybe_rejected_and_a_400_or_alert_may_mean_unexpected() {
        // Header on a new HTTP connection, then a close before any response.
        let closed = TransportFailure::new(Phase::AwaitResponseHeaders, FailureKind::ClosedBeforeResponse, "closed");
        let f = diagnose(Protocol::Http, attempt(Some(header(ProxyHeaderFormat::V1, true)), Some(closed.clone())), ProtocolStatus::None);
        let d = find(&f, "tcp.proxy_header_maybe_rejected").expect("maybe rejected");
        assert_eq!(d.confidence, Confidence::Unknown);
        assert!(d.alternatives.iter().any(|a| a.contains("does not expect a PROXY header")), "{:?}", d.alternatives);
        let close = find(&f, "exchange.closed_before_response").unwrap();
        assert!(close.alternatives.iter().all(|a| !a.contains(MAY_REQUIRE)), "a header was sent");
        assert!(close.alternatives.iter().any(|a| a.contains(MAY_NOT_EXPECT)), "{:?}", close.alternatives);
        // The same close on a reused connection says nothing about the header.
        let f = diagnose(Protocol::Http, reused(attempt(Some(header(ProxyHeaderFormat::V1, true)), Some(closed))), ProtocolStatus::None);
        assert!(find(&f, "tcp.proxy_header_maybe_rejected").is_none());
        // A 400 on the new connection: the public status finding keeps its
        // confidence and gains the "may not expect" alternative.
        let r = response(400);
        let st = ProtocolStatus::Http { status: 400, reason: None };
        let f = diagnose_with(Protocol::Http, attempt(Some(header(ProxyHeaderFormat::V2, true)), None), st.clone(), Some(&r));
        let d = find(&f, "http.client_error").expect("400 finding");
        assert!(d.alternatives.iter().any(|a| a.contains(MAY_NOT_EXPECT)), "{:?}", d.alternatives);
        assert!(find(&f, "tcp.proxy_header_maybe_rejected").is_none(), "the listener answered; no rejection claim");
        assert!(
            f.iter().all(|x| !(x.confidence == Confidence::Confirmed && x.explanation.contains("PROXY"))),
            "never a confirmed PROXY cause"
        );
        let plain = diagnose_with(Protocol::Http, attempt(None, None), st.clone(), Some(&r));
        assert!(
            find(&plain, "http.client_error").unwrap().alternatives.iter().all(|a| !a.contains(MAY_NOT_EXPECT)),
            "no header, no alternative"
        );
        let other = response(404);
        let f = diagnose_with(
            Protocol::Http,
            attempt(Some(header(ProxyHeaderFormat::V2, true)), None),
            ProtocolStatus::Http { status: 404, reason: None },
            Some(&other),
        );
        assert!(f.iter().all(|x| x.alternatives.iter().all(|a| !a.contains(MAY_NOT_EXPECT))), "only 400 reads as a garbled request");
        // A TLS alert during the handshake after the header.
        let mut alert = TransportFailure::new(Phase::TlsHandshake, FailureKind::TlsAlertReceived, "alert");
        alert.tls_alert = Some("decode_error".into());
        let f = diagnose(Protocol::Grpc, attempt(Some(header(ProxyHeaderFormat::V2, true)), Some(alert)), ProtocolStatus::None);
        let d = find(&f, "client.tls.peer_alert").expect("alert finding");
        assert!(d.alternatives.iter().any(|a| a.contains(MAY_NOT_EXPECT)));
        assert_eq!(d.confidence, Confidence::Unknown);
    }

    #[test]
    fn a_close_after_a_well_formed_header_is_unknown_and_after_a_malformed_one_likely() {
        for by in [ClosedBy::Peer, ClosedBy::Abnormal] {
            let f = diagnose(Protocol::Tcp, attempt(Some(header(ProxyHeaderFormat::V2, true)), None), tcp(0, by));
            let d = find(&f, "tcp.proxy_header_maybe_rejected").expect("maybe rejected");
            assert_eq!(d.confidence, Confidence::Unknown);
            assert!(d.does_not_prove.iter().any(|x| x.contains("rejected")), "{:?}", d.does_not_prove);
            assert!(d.alternatives.iter().any(|a| a.contains("trusted")));
            let close = find(&f, "tcp.closed_without_data").unwrap();
            assert!(close.alternatives.iter().all(|a| !a.contains(MAY_REQUIRE)), "a header was sent");
        }
        let f = diagnose(Protocol::Tcp, attempt(Some(header(ProxyHeaderFormat::Raw, false)), None), tcp(0, ClosedBy::Peer));
        let d = find(&f, "tcp.proxy_header_maybe_rejected").unwrap();
        assert_eq!(d.confidence, Confidence::Likely);
        assert!(d.explanation.contains("invalid PROXY v2 signature"), "{}", d.explanation);
        // TLS handshake closed after the header.
        let fail = TransportFailure::new(Phase::TlsHandshake, FailureKind::TlsReset, "reset");
        let f = diagnose(Protocol::Tcp, attempt(Some(header(ProxyHeaderFormat::V1, true)), Some(fail)), ProtocolStatus::None);
        assert_eq!(find(&f, "tcp.proxy_header_maybe_rejected").unwrap().confidence, Confidence::Unknown);
        // Data came back: the header was evidently accepted; nothing to say.
        let ok = diagnose(Protocol::Tcp, attempt(Some(header(ProxyHeaderFormat::V2, true)), None), tcp(5, ClosedBy::Peer));
        assert!(find(&ok, "tcp.proxy_header_maybe_rejected").is_none());
    }

    #[test]
    fn udp_silence_after_an_envelope_stays_no_response_observed() {
        let st = ProtocolStatus::Udp { datagrams_sent: 1, datagrams_received: 0, window_ms: 500, masque: None };
        let f = diagnose(Protocol::Udp, attempt(Some(header(ProxyHeaderFormat::V2Datagram, true)), None), st.clone());
        let d = find(&f, "udp.no_response").expect("no response");
        assert!(d.alternatives.iter().any(|a| a.contains("dropped the PROXY v2 envelope")), "{:?}", d.alternatives);
        assert!(f.iter().all(|x| !x.code.contains("proxy_header")), "no new claim for silence");
        let plain = diagnose(Protocol::Udp, attempt(None, None), st);
        assert!(find(&plain, "udp.no_response").unwrap().alternatives.iter().all(|a| !a.contains("envelope")));
    }
}
