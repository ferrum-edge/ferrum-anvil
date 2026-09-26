use super::Ctx;
use crate::{Draft, warn};
use anvil_domain::diagnostics::{Confidence, EvidenceSource as E, Owner, Severity, SourceScope};
use anvil_domain::execution::{FailureKind as K, PeerIdentityCheck, TlsObservation, TlsVerification};
use anvil_domain::outcome::{OutcomeWarning, WarningCode};

/// Alerts that specifically concern the client's certificate.
const CLIENT_CERT_ALERTS: &[&str] = &[
    "bad_certificate",
    "unsupported_certificate",
    "certificate_revoked",
    "certificate_expired",
    "certificate_unknown",
    "unknown_ca",
    "access_denied",
];

pub fn rules(ctx: &Ctx<'_>, out: &mut Vec<Draft>, warnings: &mut Vec<OutcomeWarning>) {
    // Verification bypass warning applies to successful and failed exchanges alike.
    for a in ctx.input.attempts {
        if let Some(t) = a.connection.as_ref().and_then(|c| c.tls.as_ref())
            && let TlsVerification::Bypassed { would_have_failed } = &t.verification
        {
            warn(
                warnings,
                WarningCode::InsecureTls,
                "Certificate verification was disabled for this request; the peer was not authenticated.",
            );
            let mut d = Draft::new(
                "client.tls.verification_bypassed",
                "tls.bypass",
                Confidence::Confirmed,
                SourceScope::ClientToPeer,
                Owner::Caller,
                Severity::Warning,
            )
            .ev_at(E::TlsVerifier, "tls.verification", "bypassed", a.index)
            .var("host", ctx.target_host());
            if let Some(k) = would_have_failed {
                d = d.ev_at(E::TlsVerifier, "tls.would_have_failed", format!("{k:?}"), a.index).var("would", describe_verification(*k));
            } else {
                d = d.var("would", "passed or was not evaluated".to_string());
            }
            out.push(d);
            break;
        }
    }

    let Some(a) = ctx.final_attempt() else { return };
    let Some(f) = a.failure.as_ref() else { return };
    let tls = a.connection.as_ref().and_then(|c| c.tls.as_ref());
    let host = ctx.target_host();
    let base = |code: &str, rule: &'static str, conf: Confidence, owner: Owner| {
        let mut d = Draft::new(code, rule, conf, SourceScope::ClientToPeer, owner, Severity::Error)
            .ev_at(E::NativeTransport, "failure.kind", format!("{:?}", f.kind), a.index)
            .ev_at(E::NativeTransport, "failure.phase", format!("{:?}", f.phase), a.index)
            .var("host", host.clone())
            .var("message", f.message.clone())
            .var("deadline_ms", f.deadline_ms.map(|d| d.to_string()).unwrap_or_else(|| "the configured".into()));
        if let Some(t) = tls {
            if let Some(leaf) = t.peer_certificates.first() {
                d = d
                    .ev_at(E::TlsVerifier, "peer.subject", leaf.subject.clone(), a.index)
                    .ev_at(E::TlsVerifier, "peer.issuer", leaf.issuer.clone(), a.index)
                    .ev_at(E::TlsVerifier, "peer.san", leaf.subject_alt_names.join(", "), a.index)
                    .ev_at(E::TlsVerifier, "peer.validity", format!("{} → {}", leaf.not_before, leaf.not_after), a.index)
                    .var("subject", leaf.subject.clone())
                    .var("issuer", leaf.issuer.clone())
                    .var("not_after", leaf.not_after.clone())
                    .var("not_before", leaf.not_before.clone())
                    .var("sans", if leaf.subject_alt_names.is_empty() { "none".into() } else { leaf.subject_alt_names.join(", ") });
            }
            d = d.ev_at(E::TlsVerifier, "tls.server_name", t.server_name.clone(), a.index).var("server_name", t.server_name.clone());
            d = identity_evidence(d, t, a.index);
            if let Some(req) = t.client_certificate_requested {
                d = d.ev_at(E::NativeTransport, "tls.client_cert_requested", req.to_string(), a.index);
            }
            d = d.ev_at(
                E::NativeTransport,
                "tls.client_cert_presented",
                t.client_certificate_presented.as_ref().map(|c| c.subject.clone()).unwrap_or_else(|| "none".into()),
                a.index,
            );
            if let Some(c) = &t.client_certificate_presented {
                d = d.var("client_subject", c.subject.clone());
            }
        }
        if let Some(al) = &f.tls_alert {
            d = d.ev_at(E::NativeTransport, "tls.alert", al.clone(), a.index).var("alert", al.clone());
        }
        d
    };

    let requested = tls.and_then(|t| t.client_certificate_requested);
    let presented = tls.map(|t| t.client_certificate_presented.is_some()).unwrap_or(false);
    let d = match f.kind {
        K::TlsUntrustedIssuer => Some(base("client.tls.untrusted_issuer", "tls.verification", Confidence::Confirmed, Owner::Caller)),
        K::TlsExpired => Some(base("client.tls.expired", "tls.verification", Confidence::Confirmed, Owner::ApiOwner)),
        K::TlsNotYetValid => Some(base("client.tls.not_yet_valid", "tls.verification", Confidence::Confirmed, Owner::Unknown)),
        K::TlsNameMismatch => {
            let mut d = base("client.tls.name_mismatch", "tls.verification", Confidence::Confirmed, Owner::Caller);
            if tls.map(|t| t.server_name_overridden).unwrap_or(false) {
                d = d.alt("The TLS profile's SNI / verification name override was used for this check instead of the URL host.");
            }
            Some(d)
        }
        K::TlsSpiffeIdMismatch => {
            Some(spiffe(base("client.tls.spiffe_id_mismatch", "tls.verification", Confidence::Confirmed, Owner::Caller), tls))
        }
        K::TlsUntrustedTrustDomain => {
            Some(spiffe(base("client.tls.untrusted_trust_domain", "tls.verification", Confidence::Confirmed, Owner::Caller), tls))
        }
        K::TlsInvalidSvid => Some(spiffe(base("client.tls.invalid_svid", "tls.verification", Confidence::Confirmed, Owner::ApiOwner), tls)),
        K::TlsRevoked => Some(base("client.tls.revoked", "tls.verification", Confidence::Confirmed, Owner::ApiOwner)),
        K::TlsBadCertificate => Some(base("client.tls.bad_certificate", "tls.verification", Confidence::Confirmed, Owner::ApiOwner)),
        K::TlsAlertReceived | K::TlsAlertAfterHandshake => {
            let alert = f.tls_alert.clone().unwrap_or_default();
            if alert == "certificate_required" && !presented {
                // RFC 8446 §6.2: certificate_required is sent precisely when a
                // client certificate was required and none was provided.
                Some(base("client.tls.client_cert_required", "tls.handshake", Confidence::Confirmed, Owner::Caller))
            } else if presented
                && (CLIENT_CERT_ALERTS.contains(&alert.as_str())
                    // TLS 1.3: after the client's Finished, the peer's only
                    // remaining handshake decision is the client certificate
                    // (Ferrum Edge 0.9.7 mesh listeners answer an untrusted
                    // trust domain this way).
                    || (f.kind == K::TlsAlertAfterHandshake && alert == "handshake_failure"))
            {
                Some(base("client.tls.client_cert_rejected", "tls.handshake", Confidence::Likely, Owner::Caller))
            } else if alert == "handshake_failure" && requested == Some(true) && !presented {
                Some(
                    base("client.tls.client_cert_probably_required", "tls.handshake", Confidence::Likely, Owner::Caller)
                        .alt("The peer and Anvil share no acceptable cipher suite or signature algorithm."),
                )
            } else if alert == "protocol_version" {
                Some(base("client.tls.version_mismatch", "tls.handshake", Confidence::Confirmed, Owner::Unknown))
            } else {
                Some(base("client.tls.peer_alert", "tls.handshake", Confidence::Unknown, Owner::Unknown))
            }
        }
        K::TlsHandshakeTimeout => Some(base("client.tls.handshake_timeout", "tls.handshake", Confidence::Confirmed, Owner::Unknown)),
        K::TlsPeerClosed | K::TlsReset => Some(base("client.tls.connection_closed", "tls.handshake", Confidence::Unknown, Owner::Unknown)),
        K::TlsProtocolMismatch => Some(base("client.tls.not_tls", "tls.handshake", Confidence::Likely, Owner::Caller)),
        K::TlsAlpnMismatch => Some(base("client.tls.alpn_mismatch", "tls.handshake", Confidence::Confirmed, Owner::Unknown)),
        K::TlsOther => Some(base("client.tls.other", "tls.handshake", Confidence::Unknown, Owner::Unknown)),
        // TLS 1.3 refusal whose alert was lost: the peer asked for a client
        // certificate, the client finished its side of the handshake, and the
        // fresh connection then closed before any response without a
        // readable alert (the peer's reset can discard the alert).
        K::ClosedBeforeResponse | K::ResetBeforeResponse | K::RequestWriteFailed
            if f.tls_alert.is_none()
                && requested == Some(true)
                && tls.and_then(|t| t.version.as_deref()) == Some("TLSv1_3")
                && a.connection.as_ref().map(|c| !c.reused && c.prior_requests == 0).unwrap_or(false) =>
        {
            let presented_subject = tls.and_then(|t| t.client_certificate_presented.as_ref()).map(|c| c.subject.clone());
            let (conf, cert) = match presented_subject {
                Some(s) => (Confidence::Unknown, s),
                None => (Confidence::Likely, "no client certificate".to_string()),
            };
            Some(base("client.tls.closed_after_certificate_request", "tls.handshake", conf, Owner::Caller).var("client_cert", cert))
        }
        _ => None,
    };
    if let Some(d) = d {
        out.push(d);
    }
}

/// Identity evidence recorded for every TLS failure finding: the SNI sent,
/// the identity check applied and the peer's SPIFFE ID.
pub fn identity_evidence(mut d: Draft, t: &TlsObservation, attempt: u32) -> Draft {
    d = d.ev_at(E::NativeTransport, "tls.sni", t.sni.clone().unwrap_or_else(|| "none (IP address or not sent)".into()), attempt);
    if t.server_name_overridden {
        d = d.ev_at(E::Configuration, "tls.server_name_override", t.server_name.clone(), attempt);
    }
    if let Some(c) = &t.identity_check {
        d = d.ev_at(E::TlsVerifier, "tls.identity_check", describe_check(c), attempt).var("identity_check", describe_check(c));
    }
    if let Some(id) = &t.peer_spiffe_id {
        d = d.ev_at(E::TlsVerifier, "peer.spiffe_id", id.clone(), attempt);
    }
    d
}

/// SPIFFE-specific variables (expected identity, presented ID, detail).
fn spiffe(mut d: Draft, tls: Option<&TlsObservation>) -> Draft {
    let Some(t) = tls else { return d };
    d = d.var("peer_spiffe_id", t.peer_spiffe_id.clone().unwrap_or_else(|| "no single SPIFFE ID".into()));
    match &t.identity_check {
        Some(PeerIdentityCheck::SpiffeId { expected, trust_domain }) => {
            d = d.var("expected", expected.clone()).var("trust_domain", trust_domain.clone());
        }
        Some(PeerIdentityCheck::SpiffeTrustDomain { trust_domain }) => {
            d = d.var("expected", format!("any SPIFFE ID in trust domain {trust_domain}")).var("trust_domain", trust_domain.clone());
        }
        _ => {}
    }
    if let TlsVerification::Failed { detail, .. } = &t.verification {
        d = d.var("detail", detail.clone());
    }
    d
}

/// Plain-language identity check, for evidence and wording.
pub fn describe_check(c: &PeerIdentityCheck) -> String {
    match c {
        PeerIdentityCheck::HostName { name } => format!("host name {name}"),
        PeerIdentityCheck::SpiffeId { expected, .. } => format!("SPIFFE ID {expected}"),
        PeerIdentityCheck::SpiffeTrustDomain { trust_domain } => format!("SPIFFE trust domain {trust_domain}"),
    }
}

pub fn describe_verification(k: K) -> String {
    match k {
        K::TlsSpiffeIdMismatch => "the certificate's SPIFFE ID is not the expected one".into(),
        K::TlsUntrustedTrustDomain => "the certificate's SPIFFE trust domain is not trusted".into(),
        K::TlsInvalidSvid => "the certificate is not a valid X.509-SVID".into(),
        K::TlsUntrustedIssuer => "the certificate is not issued by a trusted authority".into(),
        K::TlsExpired => "the certificate has expired".into(),
        K::TlsNotYetValid => "the certificate is not yet valid".into(),
        K::TlsNameMismatch => "the certificate does not match the host name".into(),
        K::TlsRevoked => "the certificate is revoked".into(),
        _ => "the certificate is not acceptable".into(),
    }
}
