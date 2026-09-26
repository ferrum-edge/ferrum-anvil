//! PROXY protocol evidence on stream sessions.
//!
//! A stream listener that requires PROXY protocol (Ferrum Edge
//! `stream_proxy_protocol: true`) closes a TCP connection immediately — no
//! data, no reason — when the header is missing, malformed or comes from an
//! untrusted peer, and silently drops datagrams whose envelope fails. A bare
//! close or silence is therefore never enough to claim any of these causes:
//!
//! * no header was sent and the peer closed without data: the existing close
//!   finding gains "the listener may require PROXY protocol" as one more
//!   alternative (no claim, no confidence of its own);
//! * a header was sent and the peer closed without data:
//!   `tcp.proxy_header_maybe_rejected`, `unknown` — or `likely` when Anvil's
//!   own check of the bytes it sent found them malformed;
//! * an envelope was sent and nothing came back: the no-response finding
//!   gains "the listener may have dropped the envelope" as an alternative.

use super::Ctx;
use crate::Draft;
use anvil_domain::diagnostics::{Confidence, EvidenceSource as E, Owner, Severity, SourceScope};
use anvil_domain::execution::FailureKind as K;
use anvil_domain::outcome::{ClosedBy, ProtocolStatus};
use anvil_domain::proxy_protocol::{ProxyHeaderFormat, ProxyHeaderObservation};
use anvil_domain::request::Protocol;

const HEADER_MAY_BE_REQUIRED: &str = "alt.proxy_protocol.header_may_be_required";
const ENVELOPE_MAY_BE_DROPPED: &str = "alt.proxy_protocol.envelope_may_be_dropped";

fn sent_header<'a>(ctx: &Ctx<'a>) -> Option<&'a ProxyHeaderObservation> {
    ctx.final_attempt().and_then(|a| a.connection.as_ref()).and_then(|c| c.proxy_header.as_ref())
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
    match ctx.final_failure().map(|f| f.kind) {
        Some(K::TlsPeerClosed | K::TlsReset) => Some("closed or reset the connection during the TLS handshake"),
        _ => None,
    }
}

pub fn rules(ctx: &Ctx<'_>, out: &mut Vec<Draft>) {
    if ctx.input.protocol != Protocol::Tcp {
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

/// Attach PROXY-protocol alternatives to the close / silence findings other
/// rules produced. Runs after every other rule.
pub fn annotate(ctx: &Ctx<'_>, drafts: &mut [Draft]) {
    let header = sent_header(ctx);
    match ctx.input.protocol {
        Protocol::Tcp if header.is_none() => {
            for d in drafts.iter_mut().filter(|d| matches!(d.code.as_str(), "tcp.closed_without_data" | "client.tls.connection_closed")) {
                d.alt_fragments.push(HEADER_MAY_BE_REQUIRED);
            }
        }
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
        let trust = FerrumTrust::NotConfigured;
        let attempts = [a];
        let input = DiagnosticInput {
            protocol,
            method: "TCP",
            preparation_failure: None,
            attempts: &attempts,
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

    fn tcp(received: u64, by: ClosedBy) -> ProtocolStatus {
        ProtocolStatus::Tcp { bytes_sent: 6, bytes_received: received, half_closed: false, closed_by: by }
    }

    fn find<'a>(f: &'a [DiagnosticFinding], code: &str) -> Option<&'a DiagnosticFinding> {
        f.iter().find(|x| x.code == code)
    }

    const MAY_REQUIRE: &str = "may require a PROXY protocol header";

    #[test]
    fn fragments_are_worded_in_the_catalog() {
        let c = crate::render::catalog();
        for k in [super::HEADER_MAY_BE_REQUIRED, super::ENVELOPE_MAY_BE_DROPPED] {
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
    fn a_tls_close_during_the_handshake_without_a_header_gets_the_alternative_on_tcp_only() {
        let fail = TransportFailure::new(Phase::TlsHandshake, FailureKind::TlsPeerClosed, "eof");
        let f = diagnose(Protocol::Tcp, attempt(None, Some(fail.clone())), ProtocolStatus::None);
        let d = find(&f, "client.tls.connection_closed").expect("tls close");
        assert!(d.alternatives.iter().any(|a| a.contains(MAY_REQUIRE)));
        assert_eq!(d.confidence, Confidence::Unknown);
        let http = diagnose(Protocol::Http, attempt(None, Some(fail)), ProtocolStatus::None);
        assert!(find(&http, "client.tls.connection_closed").unwrap().alternatives.iter().all(|a| !a.contains(MAY_REQUIRE)));
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
