use super::Ctx;
use crate::{Draft, warn};
use anvil_domain::diagnostics::{Confidence, EvidenceSource as E, Owner, Severity, SourceScope};
use anvil_domain::execution::{FailureKind as K, TlsVerification};
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
        K::TlsNameMismatch => Some(base("client.tls.name_mismatch", "tls.verification", Confidence::Confirmed, Owner::Caller)),
        K::TlsRevoked => Some(base("client.tls.revoked", "tls.verification", Confidence::Confirmed, Owner::ApiOwner)),
        K::TlsBadCertificate => Some(base("client.tls.bad_certificate", "tls.verification", Confidence::Confirmed, Owner::ApiOwner)),
        K::TlsAlertReceived | K::TlsAlertAfterHandshake => {
            let alert = f.tls_alert.clone().unwrap_or_default();
            if alert == "certificate_required" && !presented {
                // RFC 8446 §6.2: certificate_required is sent precisely when a
                // client certificate was required and none was provided.
                Some(base("client.tls.client_cert_required", "tls.handshake", Confidence::Confirmed, Owner::Caller))
            } else if presented && CLIENT_CERT_ALERTS.contains(&alert.as_str()) {
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
        _ => None,
    };
    if let Some(d) = d {
        out.push(d);
    }
}

pub fn describe_verification(k: K) -> String {
    match k {
        K::TlsUntrustedIssuer => "the certificate is not issued by a trusted authority".into(),
        K::TlsExpired => "the certificate has expired".into(),
        K::TlsNotYetValid => "the certificate is not yet valid".into(),
        K::TlsNameMismatch => "the certificate does not match the host name".into(),
        K::TlsRevoked => "the certificate is revoked".into(),
        _ => "the certificate is not acceptable".into(),
    }
}
